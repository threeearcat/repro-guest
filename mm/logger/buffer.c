#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>

#include <linux/syscall_logger.h>

#include "buffer.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dae R. Jeong");

DEFINE_PER_CPU(void *, rpr_log_buf);
static DEFINE_PER_CPU(unsigned long, rpr_log_idx);

struct syscall_logger_ops __logger_ops;

static int __init syscall_logger_init(void)
{
	int cpu;
	void *buf;

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

	debug_init();

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

	debug_exit();

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

static unsigned long syscall_logger_log_syscall_entry(unsigned long nr, const struct pt_regs *regs)
{
	unsigned long idx, flags;
	struct syscall_log_entry *entry;
	ktime_t ktime_zero = { .tv64 = 0 };
	void *buf = RPR_LOGBUF_CURCPU;

	/* This function should disable local irq in order to save entry
	 * atomically.
	 * TODO: Can I make this function as a transaction like slub?
	 */
	local_irq_save(flags);
	idx = this_cpu_read(rpr_log_idx);

	entry = ((struct syscall_log_entry *)buf + idx);

	/* See do_syscall_64. */
	entry->nr = nr;
	entry->rdi = regs->di;
	entry->rsi = regs->si;
	entry->rdx = regs->dx;
	entry->r10 = regs->r10;
	entry->r8 = regs->r8;
	entry->r9 = regs->r9;

	/* Log entry_time first. exit_time will be logged later. */
	entry->entry_time = ktime_get();
	entry->exit_time = ktime_zero;

	/* TODO: Change with bit operation */
	this_cpu_write(rpr_log_idx, (idx + 1) % (unsigned long)NR_MAX_ENTRY);

	local_irq_restore(flags);
	return idx;
}

static void syscall_logger_log_syscall_exit(unsigned long idx)
{
	/* Unlike syscall_logger_log_syscall_entry(), we don't need to
	 * disable local irq here as long as any other syscalls can have
	 * same idx.
	 */

	void *buf = RPR_LOGBUF_CURCPU;
	struct syscall_log_entry *entry;
	ktime_t ktime_zero = { .tv64 = 0 };

	entry = ((struct syscall_log_entry *)buf + idx);
	if (ktime_equal(entry->exit_time, ktime_zero)) {
		entry->exit_time = ktime_get();
	} else {
		/* Other syscall already wrote timestamp on this entry. It
		 * must not be happend.
		 */
		BUG();
	}

	/* Don't return an error code in this function. If this function
	 * fails, just kill a kernel.
	 */
}

struct syscall_logger_ops __logger_ops = {
    .log_one_syscall = syscall_logger_log_syscall_entry,
    .log_syscall_exit = syscall_logger_log_syscall_exit,
};

module_init(syscall_logger_init);
module_exit(syscall_logger_exit);
