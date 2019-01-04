#include <linux/kernel.h>
#include <linux/syscalls.h>

struct test_struct {
	int a;
	char b;
};

SYSCALL_DEFINE1(copy_from_user_test, char * __user, buf) {
	struct test_struct test;
	copy_from_user(&test, buf, sizeof(struct test_struct));
	printk("test.a:\t%d\ntest.b:\t%d\n", test.a, test.b);
	return 0;
}
