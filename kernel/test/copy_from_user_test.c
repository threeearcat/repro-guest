#include <linux/kernel.h>
#include <linux/syscalls.h>

struct test_struct {
	int a;
	char b;
};

SYSCALL_DEFINE1(copy_from_user_test, char * __user, buf) {
	struct test_struct test;
	copy_from_user(&test, buf, sizeof(struct test_struct));
	printk("test.a:\t%d\n", test.a);
	printk("test.b:\t%d\n", test.b);
	return 0;
}

SYSCALL_DEFINE1(copy_to_user_test, char * __user, buf)  {
	struct test_struct test = {.a = 10, .b = 30};
	printk("test.a:\t%d\n", test.a);
	printk("test.b:\t%d\n", test.b);
	copy_to_user(buf, &test, sizeof(struct test_struct));
	return 0;
}

SYSCALL_DEFINE1(get_user_test, long * __user, buf)  {
	long var;
	get_user(var, buf);
	printk("var:\t%lx\n", var);
	return 0;
}

SYSCALL_DEFINE1(put_user_test, long * __user, buf)  {
	long var = 0xdead;
	printk("var:\t%lx\n", var);
	put_user(var, buf);
	return 0;
}
