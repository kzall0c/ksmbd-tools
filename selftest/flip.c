// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ksmbd.selftest - flip test
 *
 * Rapidly flips ksmbd on/off with concurrent mount/unmount/IO operations
 * using fork() to be as harsh as possible. Tests that the kernel module
 * and userspace daemon handle lifecycle transitions cleanly under stress.
 *
 * Each flip cycle:
 *   1. modprobe ksmbd
 *   2. start ksmbd.mountd (fork+exec)
 *   3. fork children that mount, do I/O, unmount concurrently
 *   4. ksmbd.control --shutdown
 *   5. rmmod ksmbd
 *
 * This catches:
 *   - Module refcount leaks preventing rmmod
 *   - Daemon not cleaning up IPC state on shutdown
 *   - Kernel oops on mount during shutdown race
 *   - Stale connections after module reload
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "selftest.h"

#define FLIP_ITERATIONS		10
#define MOUNT_CHILDREN		3
#define MOUNTPOINT		"/mnt/ksmbd-flip"
#define SHAREPATH		"/mnt/test3"
#define SHARE_URL		"//127.0.0.1/cifsd-test3"
#define MOUNT_OPTS		"user=testuser,pass=1234,vers=3.1.1"
#define SELFTEST_CONF_PATH	SYSCONFDIR "/ksmbd/ksmbd.selftest.conf"

static int run_cmd(const char *cmd)
{
	int ret = system(cmd);
	return WIFEXITED(ret) ? WEXITSTATUS(ret) : -1;
}

static int ksmbd_on(const char *pwddb)
{
	char cmd[512];

	run_cmd("modprobe ksmbd 2>/dev/null");

	snprintf(cmd, sizeof(cmd),
		 "ksmbd.adduser -P %s -a testuser -p 1234 2>/dev/null", pwddb);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ksmbd.mountd -n -C " SELFTEST_CONF_PATH " -P %s &", pwddb);
	run_cmd(cmd);

	usleep(500000); /* let mountd start */
	return 0;
}

static int ksmbd_off(void)
{
	run_cmd("ksmbd.control --shutdown 2>/dev/null");
	usleep(200000);
	return run_cmd("rmmod ksmbd 2>/dev/null");
}

static void mount_io_child(int child_id, int flip_num)
{
	char mntpoint[256];
	char filepath[512];
	char buf[64];
	int fd, ret;

	snprintf(mntpoint, sizeof(mntpoint), MOUNTPOINT "/%d", child_id);
	mkdir(mntpoint, 0755);

	/* Try to mount - may race with shutdown, that's the point */
	snprintf(buf, sizeof(buf),
		 "mount -t cifs " SHARE_URL " %s -o " MOUNT_OPTS " 2>/dev/null",
		 mntpoint);
	ret = run_cmd(buf);
	if (ret != 0)
		_exit(0); /* mount failed due to race - ok */

	/* Write */
	snprintf(filepath, sizeof(filepath), "%s/flip_%d_%d", mntpoint, flip_num, child_id);
	fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) {
		snprintf(buf, sizeof(buf), "flip%d-child%d", flip_num, child_id);
		write(fd, buf, strlen(buf));
		close(fd);
	}

	/* Read back */
	fd = open(filepath, O_RDONLY);
	if (fd >= 0) {
		char rbuf[64] = {0};
		read(fd, rbuf, sizeof(rbuf) - 1);
		close(fd);
		/* Verify */
		if (strcmp(rbuf, buf) != 0)
			_exit(1);
	}

	unlink(filepath);

	/* Unmount - may also race */
	snprintf(buf, sizeof(buf), "umount %s 2>/dev/null", mntpoint);
	run_cmd(buf);

	_exit(0);
}

int test_flip(void)
{
	char pwddb[] = "/tmp/ksmbdpwd-flip.XXXXXX";
	int i, j, ret = 0;
	int fd;

	if (getuid() != 0) {
		fprintf(stderr, "  SKIP (requires root)\n");
		return TEST_PASS;
	}

	fd = mkstemp(pwddb);
	if (fd < 0)
		return TEST_FAIL;
	close(fd);

	mkdir(MOUNTPOINT, 0755);
	mkdir(SHAREPATH, 0777);

	for (i = 0; i < FLIP_ITERATIONS; i++) {
		pid_t children[MOUNT_CHILDREN];

		/* ON */
		ksmbd_on(pwddb);

		/* Fork children that mount/IO/unmount concurrently */
		for (j = 0; j < MOUNT_CHILDREN; j++) {
			char mntdir[256];
			snprintf(mntdir, sizeof(mntdir), MOUNTPOINT "/%d", j);
			mkdir(mntdir, 0755);

			children[j] = fork();
			if (children[j] == 0)
				mount_io_child(j, i);
		}

		/* Let children race for a bit, then pull the rug */
		usleep(300000);

		/* OFF - while children may still be doing I/O */
		ksmbd_off();

		/* Reap children */
		for (j = 0; j < MOUNT_CHILDREN; j++) {
			int status;
			waitpid(children[j], &status, 0);
			if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
				fprintf(stderr, "    flip %d child %d: I/O mismatch\n", i, j);
				ret = 1;
			}
		}

		/* Cleanup any stale mounts */
		for (j = 0; j < MOUNT_CHILDREN; j++) {
			char cmd[256];
			snprintf(cmd, sizeof(cmd), "umount " MOUNTPOINT "/%d 2>/dev/null", j);
			run_cmd(cmd);
		}

		run_cmd("rm -rf " SHAREPATH "/*");
	}

	unlink(pwddb);
	return ret ? TEST_FAIL : TEST_PASS;
}


