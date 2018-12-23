#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

char *buf;

#pragma GCC push_options
#pragma GCC optimize ("O0")

#define STR "Writing to buffer"
SYSCALL_DEFINE0(race1) {

	printk("&buf: %p\n", &buf);
	buf = kmalloc(1024, GFP_KERNEL);
	if (buf) {
		// race window
		memcpy(buf, STR, strlen(STR));
		buf[strlen(STR)] = 0;
		printk(KERN_INFO "%s\n", buf);
		kfree(buf);
	}

	return 0;
}

SYSCALL_DEFINE0(race2) {

	buf = NULL;
	return 0;
}


#pragma GCC pop_options
