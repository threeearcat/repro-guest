#ifndef __COPY_FROM_USER_LOGGER_H
#define __COPY_FROM_USER_LOGGER_H

#include <linux/kernel.h>
#include <linux/compiler.h>

struct test_struct;
#define copy_from_user_check_type(to, from, n) \
	_Generic(to,							   \
			 struct test_struct *: true,	   \
			 default: false)

struct copy_from_user_logger_ops {
	void (*record_copy_from_user)(void *to, const void *from, unsigned long n, bool dump_data);
	void (*record_copy_to_user)(void *to, const void *from, unsigned long n, bool dump_data);
};

extern struct copy_from_user_logger_ops *copy_from_user_logger_ops;

#endif /* __COPY_FROM_USER_LOGGER_H */
