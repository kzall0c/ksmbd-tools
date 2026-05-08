// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ksmbd.selftest - user management race condition tests
 *
 * These tests exercise bugs in tools/management/user.c that can
 * corrupt data sent to the ksmbd kernel module via netlink IPC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <glib.h>

#include "linux/ksmbd_server.h"
#include "management/user.h"
#include "tools.h"
#include "selftest.h"

/*
 * Bug #1: put_ksmbd_user use-after-free
 *
 * put_ksmbd_user() drops update_lock after setting ref_count=0,
 * then calls usm_remove_user() which frees the user. Between the
 * unlock and the free, another thread can find the user in the hash
 * table via usm_lookup_user(), call get_ksmbd_user(), and increment
 * ref_count from 0→1. Then usm_remove_user frees it → UAF.
 *
 * Impact: freed user's password hash gets sent to kernel via
 * __handle_login_request → kernel authenticates against garbage.
 */

#define RACE_ITERATIONS		10000
#define NUM_THREADS		4

static volatile int race_stop;

static void *lookup_put_thread(void *arg)
{
	while (!race_stop) {
		struct ksmbd_user *user = usm_lookup_user("raceuser");

		if (user)
			put_ksmbd_user(user);
	}
	return NULL;
}

static void *add_remove_thread(void *arg)
{
	int i;

	for (i = 0; i < RACE_ITERATIONS && !race_stop; i++) {
		usm_add_new_user(g_strdup("raceuser"),
				 g_strdup("cGFzcw=="));
		usm_remove_all_users();
	}
	return NULL;
}

static int test_user_uaf_race(void)
{
	pthread_t threads[NUM_THREADS];
	int i;

	usm_init();
	race_stop = 0;

	/* Half threads do lookup+put, half do add+remove */
	for (i = 0; i < NUM_THREADS / 2; i++)
		pthread_create(&threads[i], NULL, lookup_put_thread, NULL);
	for (; i < NUM_THREADS; i++)
		pthread_create(&threads[i], NULL, add_remove_thread, NULL);

	/* Wait for add/remove threads to finish */
	for (i = NUM_THREADS / 2; i < NUM_THREADS; i++)
		pthread_join(threads[i], NULL);

	race_stop = 1;
	for (i = 0; i < NUM_THREADS / 2; i++)
		pthread_join(threads[i], NULL);

	usm_destroy();
	return TEST_PASS;
}

/*
 * Bug #2: usm_handle_login_request_ext reads ngroups/sgid without lock
 *
 * In usm_handle_login_request_ext():
 *   resp->ngroups = user->ngroups;
 *   memcpy(resp->____payload, user->sgid, sizeof(gid_t) * user->ngroups);
 *
 * Neither ngroups nor sgid is read under update_lock. If another thread
 * frees the user concurrently (via usm_remove_all_users), sgid is freed
 * → heap UAF. The corrupted data is sent to kernel via netlink.
 *
 * Also TOCTOU: login_response_payload_sz() reads ngroups, allocates buffer,
 * then usm_handle_login_request_ext() reads ngroups again — if it grew,
 * memcpy overflows the allocated buffer → heap overflow sent to kernel.
 */

static void *login_ext_thread(void *arg)
{
	struct ksmbd_login_request req = {0};
	int i;

	strncpy(req.account, "extuser", sizeof(req.account) - 1);

	for (i = 0; i < RACE_ITERATIONS && !race_stop; i++) {
		struct ksmbd_login_response_ext *resp;
		int payload_sz;
		struct ksmbd_user *user;

		/* Simulate what worker.c login_request_ext does */
		user = usm_lookup_user(req.account);
		if (user) {
			payload_sz = sizeof(gid_t) * user->ngroups;
			put_ksmbd_user(user);
		} else {
			payload_sz = 0;
		}

		resp = g_malloc0(sizeof(*resp) + payload_sz);
		usm_handle_login_request_ext(&req, resp);
		g_free(resp);
	}
	return NULL;
}

static void *user_churn_thread(void *arg)
{
	int i;

	for (i = 0; i < RACE_ITERATIONS && !race_stop; i++) {
		usm_add_new_user(g_strdup("extuser"),
				 g_strdup("cGFzcw=="));
		usm_remove_all_users();
	}
	return NULL;
}

static int test_user_login_ext_race(void)
{
	pthread_t threads[NUM_THREADS];
	int i;

	usm_init();
	race_stop = 0;

	for (i = 0; i < NUM_THREADS / 2; i++)
		pthread_create(&threads[i], NULL, login_ext_thread, NULL);
	for (; i < NUM_THREADS; i++)
		pthread_create(&threads[i], NULL, user_churn_thread, NULL);

	for (i = NUM_THREADS / 2; i < NUM_THREADS; i++)
		pthread_join(threads[i], NULL);

	race_stop = 1;
	for (i = 0; i < NUM_THREADS / 2; i++)
		pthread_join(threads[i], NULL);

	usm_destroy();
	return TEST_PASS;
}

/*
 * Bug #3: __handle_login_request reads user fields without update_lock
 *
 * __handle_login_request reads uid, gid, flags, ngroups outside the lock,
 * then calls usm_copy_user_passhash (which does take reader lock) and
 * usm_copy_user_account (which reads user->name without lock).
 *
 * If usm_update_user_password runs concurrently, pass/pass_sz can be
 * freed and reallocated → the hash sent to kernel is from freed memory.
 */

static void *login_request_thread(void *arg)
{
	struct ksmbd_login_request req = {0};
	struct ksmbd_login_response resp;
	int i;

	strncpy(req.account, "loginuser", sizeof(req.account) - 1);

	for (i = 0; i < RACE_ITERATIONS && !race_stop; i++) {
		memset(&resp, 0, sizeof(resp));
		usm_handle_login_request(&req, &resp);
	}
	return NULL;
}

static void *password_update_thread(void *arg)
{
	int i;

	for (i = 0; i < RACE_ITERATIONS && !race_stop; i++) {
		struct ksmbd_user *user = usm_lookup_user("loginuser");

		if (user) {
			usm_update_user_password(user, "bmV3cGFzcw==");
			put_ksmbd_user(user);
		}
	}
	return NULL;
}

static int test_user_login_password_race(void)
{
	pthread_t threads[NUM_THREADS];
	int i;

	usm_init();
	usm_add_new_user(g_strdup("loginuser"), g_strdup("cGFzcw=="));
	race_stop = 0;

	for (i = 0; i < NUM_THREADS / 2; i++)
		pthread_create(&threads[i], NULL, login_request_thread, NULL);
	for (; i < NUM_THREADS; i++)
		pthread_create(&threads[i], NULL, password_update_thread, NULL);

	for (i = 0; i < NUM_THREADS; i++)
		pthread_join(threads[i], NULL);

	usm_destroy();
	return TEST_PASS;
}

/*
 * Bug #4: usm_user_name boundary validation
 *
 * usm_user_name checks name < KSMBD_REQ_MAX_ACCOUNT_NAME_SZ (48 bytes).
 * If validation is bypassed or the name is exactly 47 bytes,
 * usm_copy_user_account does memcpy into resp->account[48] without
 * null termination → kernel reads past buffer into adjacent fields.
 */

static int test_user_name_boundary(void)
{
	char name[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ + 1];
	char *p;

	/* Exactly at limit: 48 bytes → should be rejected */
	memset(name, 'A', KSMBD_REQ_MAX_ACCOUNT_NAME_SZ);
	name[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ] = '\0';
	p = name + KSMBD_REQ_MAX_ACCOUNT_NAME_SZ;
	ASSERT(!usm_user_name(name, p));

	/* One below limit: 47 bytes → should be accepted */
	name[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ - 1] = '\0';
	p = name + KSMBD_REQ_MAX_ACCOUNT_NAME_SZ - 1;
	ASSERT(usm_user_name(name, p));

	/* Empty name → should be rejected */
	ASSERT(!usm_user_name(name, name));

	/* Colon in name → should be rejected */
	ASSERT(!usm_user_name("user:name", "user:name" + 9));

	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * Bug #5: usm_handle_logout_request double put
 *
 * usm_handle_logout_request does usm_lookup_user (ref+1) then
 * put_ksmbd_user (ref-1). If two logout requests arrive for the
 * same user concurrently, both succeed in lookup, both put → the
 * second put drops ref to 0 and frees, but the first put already
 * modified flags on the same user → UAF write.
 */

static void *logout_thread(void *arg)
{
	struct ksmbd_logout_request req = {0};
	int i;

	strncpy(req.account, "logoutuser", sizeof(req.account) - 1);
	req.account_flags = KSMBD_USER_FLAG_BAD_PASSWORD;

	for (i = 0; i < RACE_ITERATIONS && !race_stop; i++)
		usm_handle_logout_request(&req);
	return NULL;
}

static int test_user_logout_race(void)
{
	pthread_t threads[NUM_THREADS];
	int i;

	usm_init();
	usm_add_new_user(g_strdup("logoutuser"), g_strdup("cGFzcw=="));
	race_stop = 0;

	for (i = 0; i < NUM_THREADS; i++)
		pthread_create(&threads[i], NULL, logout_thread, NULL);

	for (i = 0; i < NUM_THREADS; i++)
		pthread_join(threads[i], NULL);

	usm_destroy();
	return TEST_PASS;
}

struct selftest_entry user_tests[] = {
	{"user/uaf-race",		test_user_uaf_race},
	{"user/login-ext-race",		test_user_login_ext_race},
	{"user/login-password-race",	test_user_login_password_race},
	{"user/name-boundary",		test_user_name_boundary},
	{"user/logout-race",		test_user_logout_race},
	{"flip/on-off-mount-race",	test_flip},
	{NULL, NULL}
};
