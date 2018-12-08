#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>

#include <linux/syscall_logger.h>

#include "buffer.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dae R. Jeong");

DEFINE_PER_CPU(void *, rpr_log_buf);
static DEFINE_PER_CPU(int, rpr_log_idx);

struct syscall_logger_ops __logger_ops;

static int __init syscall_logger_init(void)
{
	int cpu;
	void *buf;

	debug_syscall_logger_init();

	for_each_possible_cpu(cpu) {
		/* I think we don't need contiguous pages */
		buf = vmalloc(BUFFER_SIZE);
		if (!buf)
			goto page_alloc_failed;

		RPR_LOGBUF(cpu) = buf;
		per_cpu(rpr_log_idx, cpu) = 0;
	}

	/* Now per-cpu ring buffers are made up and we can log
	 * syscalls. Let's allow syscall entry to call logger functions.
	 */
	syscall_logger_ops = &__logger_ops;

	debug_after_syscall_logger_init();

	return 0;

 page_alloc_failed:
	repro_debug("Memory allocation failed");
	for_each_possible_cpu(cpu) {
		vfree(RPR_LOGBUF(cpu));
	}

	return -ENOMEM;
}

static void __exit syscall_logger_exit(void)
{
	int cpu;

	debug_syscall_logger_exit();

	/* disallow syscall entry to call logger functions first */
	syscall_logger_ops = NULL;

	/* TODO: It is possible that other CPUs are still logging
	 * syscalls. Wait until they finish their jobs.
	 */

	/* Free allocated memory */
	for_each_possible_cpu(cpu) {
		vfree(RPR_LOGBUF(cpu));
	}
}

static int syscall_logger_log_one_syscall(unsigned long nr, const struct pt_regs *regs)
{
	unsigned long flags;
	struct syscall_log_entry *entry;
	int idx;
	void *buf = RPR_LOGBUF_CURCPU;

	/* This function should disable local irq in order to save entry
	 * atomically.
	 * TODO: Can I make this function as a transaction like slub?
	 */
	local_irq_save(flags);
	idx = this_cpu_read(rpr_log_idx);;

	entry = ((struct syscall_log_entry *)buf + idx);

	/* See do_syscall_64. */
	entry->nr = nr;
	entry->rdi = regs->di;
	entry->rsi = regs->si;
	entry->rdx = regs->dx;
	entry->r10 = regs->r10;
	entry->r8 = regs->r8;
	entry->r9 = regs->r9;

	/* TODO: Change with bit operation */
	this_cpu_write(rpr_log_idx, (idx + 1) % NR_MAX_ENTRY);

	local_irq_restore(flags);
	return 0;
}

struct syscall_logger_ops __logger_ops = {
    .log_one_syscall = syscall_logger_log_one_syscall,
};

module_init(syscall_logger_init);
module_exit(syscall_logger_exit);
