// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ksmbd.selftest - C unit test runner
 *
 * Exercises internal ksmbd-tools library functions for race conditions
 * and memory corruption bugs that could send corrupted data to the
 * ksmbd kernel module via netlink IPC.
 *
 * Run under ASAN/TSAN to detect:
 *   - Use-after-free in user/share management
 *   - Heap buffer overflows in IPC response construction
 *   - Data races on ref_count, password hash, sgid arrays
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools.h"
#include "selftest.h"

static int run_tests(struct selftest_entry *tests)
{
	int total = 0, passed = 0, failed = 0;

	for (; tests->name; tests++) {
		int ret;

		fprintf(stderr, "  TEST: %s ... ", tests->name);
		ret = tests->fn();
		total++;
		if (ret == TEST_PASS) {
			fprintf(stderr, "ok\n");
			passed++;
		} else {
			fprintf(stderr, "FAIL\n");
			failed++;
		}
	}

	fprintf(stderr, "\n  %d tests: %d passed, %d failed\n",
		total, passed, failed);
	return failed ? 1 : 0;
}

int main(int argc, char **argv)
{
	int ret = 0;

	fprintf(stderr, "ksmbd.selftest: unit tests\n\n");

	ret |= run_tests(user_tests);
	ret |= run_tests(config_tests);

	return ret;
}
