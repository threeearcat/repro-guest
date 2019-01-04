#ifndef __COPY_FROM_USER_LOGGER_H
#define __COPY_FROM_USER_LOGGER_H

#include <linux/kernel.h>
#include <linux/compiler.h>

unsigned long __copy_from_user_log(void *to, const void __user *from, unsigned long n);

#endif /* __COPY_FROM_USER_LOGGER_H */
