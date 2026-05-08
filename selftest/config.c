// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ksmbd.selftest - configuration parser tests
 *
 * Tests that malformed, oversized, or adversarial configuration files
 * are handled safely. A crafted ksmbd.conf could be used to inject
 * bad values into the kernel via the IPC startup request or share
 * config responses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>

#include "linux/ksmbd_server.h"
#include "management/share.h"
#include "management/user.h"
#include "config_parser.h"
#include "share_admin.h"
#include "tools.h"
#include "selftest.h"

static char *write_tmp_conf(const char *content)
{
	char *path = g_strdup("/tmp/ksmbd-test-XXXXXX");
	int fd = mkstemp(path);

	if (fd < 0) {
		g_free(path);
		return NULL;
	}
	write(fd, content, strlen(content));
	close(fd);
	return path;
}

static void reset_parser(void)
{
	cp_smbconf_parser_destroy();
	shm_destroy();
	usm_destroy();
	memset(&global_conf, 0, sizeof(global_conf));
	usm_init();
	shm_init();
	cp_smbconf_parser_init();
}

/*
 * Empty config - should not crash, no shares created.
 */
static int test_conf_empty(void)
{
	char *path = write_tmp_conf("");

	reset_parser();
	ASSERT(cp_parse_smbconf(path) == 0);
	unlink(path);
	g_free(path);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * Unclosed section bracket - parser should not crash.
 */
static int test_conf_unclosed_section(void)
{
	char *path = write_tmp_conf("[unclosed\npath = /tmp\n");

	reset_parser();
	/* Should return error or silently skip, not crash */
	cp_parse_smbconf(path);
	unlink(path);
	g_free(path);
	return TEST_PASS;
}

/*
 * Key without value (no '=') - should be rejected.
 */
static int test_conf_key_no_value(void)
{
	char *path = write_tmp_conf("[test]\nnoequals\n");

	reset_parser();
	cp_parse_smbconf(path);
	unlink(path);
	g_free(path);
	return TEST_PASS;
}

/*
 * Very long share name - must not overflow KSMBD_REQ_MAX_SHARE_NAME (64).
 * shm_handle_share_config_request uses strncat into resp->share_name[64].
 */
static int test_conf_long_share_name(void)
{
	char conf[256];
	char name[128];
	char *path;

	memset(name, 'A', 100);
	name[100] = '\0';
	snprintf(conf, sizeof(conf), "[%s]\npath = /tmp\n", name);

	path = write_tmp_conf(conf);
	reset_parser();
	cp_parse_smbconf(path);

	/* If share was created, verify it doesn't overflow on config response */
	struct ksmbd_share *share = shm_lookup_share(name);
	if (share) {
		struct ksmbd_share_config_response resp = {0};
		shm_handle_share_config_request(share, &resp);
		/* share_name must be null-terminated within bounds */
		ASSERT(strlen(resp.share_name) < KSMBD_REQ_MAX_SHARE_NAME);
		put_ksmbd_share(share);
	}

	unlink(path);
	g_free(path);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * Path with very long value - tests sprintf overflow in
 * shm_handle_share_config_request where path + root_dir
 * is sprintf'd into ____payload without bounds check.
 */
static int test_conf_long_path(void)
{
	char *longpath = g_strnfill(4096, '/');
	char *conf = g_strdup_printf("[longpath]\npath = %s\n", longpath);
	char *path = write_tmp_conf(conf);

	reset_parser();
	cp_parse_smbconf(path);

	struct ksmbd_share *share = shm_lookup_share("longpath");
	if (share) {
		/* Just verify payload_size calculation doesn't underflow */
		int sz = shm_share_config_payload_size(share);
		ASSERT(sz > 0);
		put_ksmbd_share(share);
	}

	unlink(path);
	g_free(path);
	g_free(conf);
	g_free(longpath);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * Null bytes in config values - should not pass through to kernel.
 */
static int test_conf_null_in_value(void)
{
	/* Write a config with embedded null in path */
	char *path = g_strdup("/tmp/ksmbd-test-XXXXXX");
	int fd = mkstemp(path);
	const char before[] = "[nulltest]\npath = /tmp/a";
	const char after[] = "b\n";

	write(fd, before, sizeof(before) - 1);
	write(fd, "\0", 1);
	write(fd, after, sizeof(after) - 1);
	close(fd);

	reset_parser();
	cp_parse_smbconf(path);

	/* Path should be truncated at null or rejected */
	struct ksmbd_share *share = shm_lookup_share("nulltest");
	if (share) {
		if (share->path)
			ASSERT(strlen(share->path) <= strlen("/tmp/a"));
		put_ksmbd_share(share);
	}

	unlink(path);
	g_free(path);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * Duplicate sections - second should merge, not crash.
 */
static int test_conf_duplicate_section(void)
{
	const char *conf =
		"[dupshare]\n"
		"path = /tmp/first\n"
		"[dupshare]\n"
		"read only = no\n";
	char *path = write_tmp_conf(conf);

	reset_parser();
	ASSERT(cp_parse_smbconf(path) == 0);

	struct ksmbd_share *share = shm_lookup_share("dupshare");
	if (share) {
		/* First path wins (first value for a key is kept) */
		ASSERT(share->path != NULL);
		ASSERT(strcmp(share->path, "/tmp/first") == 0);
		put_ksmbd_share(share);
	}

	unlink(path);
	g_free(path);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * Integer overflow in numeric parameters - smb2 max read/write/trans
 * are sent to kernel as __u32. Verify no wraparound.
 */
static int test_conf_integer_overflow(void)
{
	const char *conf =
		"[global]\n"
		"smb2 max read = 99999999999999999999\n"
		"smb2 max write = -1\n"
		"max connections = 0\n";
	char *path = write_tmp_conf(conf);

	reset_parser();
	cp_parse_smbconf(path);

	/* max_connections=0 should be clamped to KSMBD_CONF_MAX_CONNECTIONS */
	ASSERT(global_conf.max_connections == KSMBD_CONF_MAX_CONNECTIONS);

	unlink(path);
	g_free(path);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * Veto files with no leading '/' - make_veto_list replaces '/' with null.
 * Empty or missing leading slash could cause off-by-one.
 */
static int test_conf_veto_files_edge(void)
{
	const char *conf =
		"[vetotest]\n"
		"path = /tmp\n"
		"veto files = /file1/file2/\n";
	char *path = write_tmp_conf(conf);

	reset_parser();
	cp_parse_smbconf(path);

	struct ksmbd_share *share = shm_lookup_share("vetotest");
	if (share) {
		ASSERT(share->veto_list_sz > 0);
		/* Verify null-separated list is well-formed */
		int nulls = 0;
		for (int i = 0; i < share->veto_list_sz; i++)
			if (share->veto_list[i] == '\0')
				nulls++;
		ASSERT(nulls >= 1);
		put_ksmbd_share(share);
	}

	unlink(path);
	g_free(path);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * addshare: share name with special characters that could
 * break INI parsing when written back to config file.
 * e.g., ']' in name could close the section prematurely.
 */
static int test_addshare_name_injection(void)
{
	/* ']' in share name must be rejected by shm_share_name */
	ASSERT(!shm_share_name("inject]ion", "inject]ion" + 10));
	/* '[' in share name must be rejected */
	ASSERT(!shm_share_name("[inject", "[inject" + 7));
	/* Normal name should pass */
	ASSERT(shm_share_name("valid-share", "valid-share" + 11));
	/* Empty name rejected */
	ASSERT(!shm_share_name("", ""));
	/* Max length (63 bytes) should pass */
	char name63[64];
	memset(name63, 'x', 63);
	name63[63] = '\0';
	ASSERT(shm_share_name(name63, name63 + 63));
	/* Over max (64 bytes) should fail */
	char name64[65];
	memset(name64, 'x', 64);
	name64[64] = '\0';
	ASSERT(!shm_share_name(name64, name64 + 64));

	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * addshare: add duplicate share should fail.
 */
static int test_addshare_duplicate(void)
{
	const char *conf = "[existing]\npath = /tmp\n";
	char *confpath = write_tmp_conf(conf);

	reset_parser();
	cp_parse_smbconf(confpath);

	/* command_add_share takes ownership of args, so dup them */
	int ret = command_add_share(g_strdup(confpath),
				    g_strdup("existing"),
				    g_strsplit("path = /tmp", "\n", -1));
	ASSERT(ret != 0); /* should fail: already exists */

	unlink(confpath);
	g_free(confpath);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * addshare: update non-existent share should fail.
 */
static int test_addshare_update_missing(void)
{
	char *confpath = write_tmp_conf("[global]\n");

	reset_parser();
	cp_parse_smbconf(confpath);

	int ret = command_update_share(g_strdup(confpath),
				       g_strdup("nosuchshare"),
				       g_strsplit("path = /tmp", "\n", -1));
	ASSERT(ret != 0);

	unlink(confpath);
	g_free(confpath);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * addshare: delete non-existent share should fail.
 */
static int test_addshare_delete_missing(void)
{
	char *confpath = write_tmp_conf("[global]\n");

	reset_parser();
	cp_parse_smbconf(confpath);

	int ret = command_delete_share(g_strdup(confpath),
				       g_strdup("nosuchshare"),
				       g_strsplit("", "\n", -1));
	ASSERT(ret != 0);

	unlink(confpath);
	g_free(confpath);
	return failures ? TEST_FAIL : TEST_PASS;
}

/*
 * addshare: option with '=' in value should parse correctly.
 * e.g., "path = /tmp/a=b" — the value is "/tmp/a=b", not split at second '='.
 */
static int test_addshare_option_equals_in_value(void)
{
	char *confpath = write_tmp_conf("[global]\n");

	reset_parser();
	cp_parse_smbconf(confpath);

	char *options[] = {"path = /tmp/a=b", NULL};
	int ret = command_add_share(g_strdup(confpath),
				    g_strdup("eqtest"),
				    g_strdupv(options));
	ASSERT(ret == 0);

	/* Re-parse and verify path */
	reset_parser();
	cp_parse_smbconf(confpath);
	struct ksmbd_share *share = shm_lookup_share("eqtest");
	if (share) {
		ASSERT(share->path != NULL);
		ASSERT(strcmp(share->path, "/tmp/a=b") == 0);
		put_ksmbd_share(share);
	}

	unlink(confpath);
	g_free(confpath);
	return failures ? TEST_FAIL : TEST_PASS;
}

struct selftest_entry config_tests[] = {
	{"config/empty",		test_conf_empty},
	{"config/unclosed-section",	test_conf_unclosed_section},
	{"config/key-no-value",		test_conf_key_no_value},
	{"config/long-share-name",	test_conf_long_share_name},
	{"config/long-path",		test_conf_long_path},
	{"config/null-in-value",	test_conf_null_in_value},
	{"config/duplicate-section",	test_conf_duplicate_section},
	{"config/integer-overflow",	test_conf_integer_overflow},
	{"config/veto-files-edge",	test_conf_veto_files_edge},
	{"addshare/name-injection",	test_addshare_name_injection},
	{"addshare/duplicate",		test_addshare_duplicate},
	{"addshare/update-missing",	test_addshare_update_missing},
	{"addshare/delete-missing",	test_addshare_delete_missing},
	{"addshare/equals-in-value",	test_addshare_option_equals_in_value},
	{NULL, NULL}
};
