/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KSMBD_SELFTEST_H__
#define __KSMBD_SELFTEST_H__

#include <stdio.h>

#define TEST_PASS	0
#define TEST_FAIL	1

static int failures;

#define ASSERT(cond) do {					\
	if (!(cond)) {						\
		fprintf(stderr, "  FAIL: %s:%d: %s\n",		\
			__FILE__, __LINE__, #cond);		\
		failures++;					\
	}							\
} while (0)

struct selftest_entry {
	const char	*name;
	int		(*fn)(void);
};

extern struct selftest_entry user_tests[];
extern struct selftest_entry config_tests[];

int test_flip(void);

#endif /* __KSMBD_SELFTEST_H__ */
