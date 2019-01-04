#include <linux/copy_from_user_logger.h>
#include <linux/kernel.h>
#include <linux/compiler.h>

unsigned long __copy_from_user_log(void *to, const void __user *from, unsigned long n)
{
	return 0;
}
