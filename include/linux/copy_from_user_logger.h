#ifndef __COPY_FROM_USER_LOGGER_H
#define __COPY_FROM_USER_LOGGER_H

#include <linux/kernel.h>
#include <linux/compiler.h>

void record_copy_from_user(void *to, const void __user *from, unsigned long n);

#endif /* __COPY_FROM_USER_LOGGER_H */
