#ifndef __COPY_FROM_USER_LOGGER_H
#define __COPY_FROM_USER_LOGGER_H

#include <linux/kernel.h>
#include <linux/compiler.h>

struct copy_from_user_logger_ops {
	void (*record_copy_from_user)(void *to, const void *from, unsigned long n);
};

extern struct copy_from_user_logger_ops *copy_from_user_logger_ops;

#endif /* __COPY_FROM_USER_LOGGER_H */
