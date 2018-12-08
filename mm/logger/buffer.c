#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>

#include "buffer.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dae R. Jeong");

DEFINE_PER_CPU(void *, rpr_log_buf);

static int __init syscall_logger_init(void)
{
	int cpu;
	void *buf;

	debug_syscall_logger_init();

	for_each_possible_cpu(cpu) {
		buf = vmalloc(BUFFER_SIZE);
		if (!buf)
			goto page_alloc_failed;

		RPR_LOGBUF(cpu) = buf;
	}

	debug_after_syscall_logger_init();

	return 0;

 page_alloc_failed:
	repro_debug("Memory allocation failed\n");
	for_each_possible_cpu(cpu) {
		vfree(RPR_LOGBUF(cpu));
	}

	return -ENOMEM;
}

static void __exit syscall_logger_exit(void)
{
	debug_syscall_logger_exit();
}

module_init(syscall_logger_init);
module_exit(syscall_logger_exit);
