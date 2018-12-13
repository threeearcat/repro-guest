#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/audit.h>

#include <linux/syscall_logger.h>

#include "buffer.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dae R. Jeong");

DEFINE_PER_CPU(struct syscall_log, syscall_log);

struct syscall_logger_ops __logger_ops;

static int __init syscall_logger_init(void)
{
	int cpu;
	void *buf;
	struct syscall_log *log;
#ifdef CONFIG_SYSCALL_LOGGER_LOG_STATISTICS
	int *stats;
#endif

	for_each_possible_cpu(cpu) {
		log = &per_cpu(syscall_log, cpu);

		/* I think contiguous pages are better in performance. I
		 * haven't conducted a measurement though.
		 */
		buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
		if (!buf)
			goto mem_alloc_failed;
		log->buf = buf;

#ifdef CONFIG_SYSCALL_LOGGER_LOG_STATISTICS
		stats = kzalloc(NR_syscalls * sizeof(unsigned int), GFP_KERNEL);
		if (!stats)
			goto mem_alloc_failed;
		log->stats = stats;
#endif

		log->idx = 0;
	}

	/* Now per-cpu ring buffers are made up and we can log
	 * syscalls. Let's allow syscall entry to call logger functions.
	 */
	syscall_logger_ops = &__logger_ops;

	debug_init();

	return 0;

 mem_alloc_failed:
	repro_debug("Mem allocation failed");
	for_each_possible_cpu(cpu) {
		log = &per_cpu(syscall_log, cpu);
		kfree(log->buf);
#ifdef CONFIG_SYSCALL_LOGGER_LOG_STATISTICS
		kfree(log->stats);
#endif
	}

	return -ENOMEM;
}

static void __exit syscall_logger_exit(void)
{
	int cpu;
	struct syscall_log *log;

	debug_exit();

	/* disallow syscall entry to call logger functions first */
	syscall_logger_ops = NULL;

	/* TODO: It is possible that other CPUs are still logging
	 * syscalls. Wait until they finish their jobs.
	 */

	/* Free allocated memory */
	for_each_possible_cpu(cpu) {
		log = &per_cpu(syscall_log, cpu);

		kfree(log->buf);
#ifdef CONFIG_SYSCALL_LOGGER_LOG_STATISTICS
		kfree(log->stats);
#endif
	}
}

static void syscall_logger_log_syscall_enter(unsigned long nr, const struct pt_regs *regs,
											 unsigned long *idxp, unsigned long *cpup)
{
	unsigned long idx, cpu, flags;
	struct syscall_log *log;
	struct syscall_log_entry *entry;
	ktime_t ktime_zero = { .tv64 = 0 };

	cpu = smp_processor_id();
	log = &per_cpu(syscall_log, cpu);

	/* This function should disable local irq in order to fetch idx
	 * atomically.
	 */
	local_irq_save(flags);
	idx = log->idx;
	log->idx = (idx + 1) & MAX_ENTRY_MASK;
	local_irq_restore(flags);

	entry = ((struct syscall_log_entry *)(log->buf) + idx);

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

#ifdef CONFIG_SYSCALL_LOGGER_LOG_STATISTICS
	/* Increase an execution number to record statistics */
	(log->stats)[nr]++;
#endif

	debug_log_syscall_enter(idx, entry);

	/* Is is possible that a syscall is migrated by a scheduler during
	 * its execution. We need to return both of idx and cpu in order
	 * not to compromise other CPUs ring buffer.
	 */
	/* TODO: Is this important to our research project? Does this give
	 * any fun chance to make things difficult?
	 */
	*idxp = idx;
	*cpup = cpu;
}

static void syscall_logger_log_syscall_exit(unsigned long idx, unsigned long cpu)
{
	/* Unlike syscall_logger_log_syscall_enter(), we don't need to
	 * disable local irq here as long as any other syscalls can have
	 * same idx.
	 */

	struct syscall_log *log;
	struct syscall_log_entry *entry;
	ktime_t ktime_zero = { .tv64 = 0 };
	char bad_happened;

	log = &per_cpu(syscall_log, cpu);
	entry = ((struct syscall_log_entry *)(log->buf) + idx);
	/* Other syscall already wrote timestamp on this entry. It
	 * must not be happend.
	 */
	bad_happened = !(ktime_equal(entry->exit_time, ktime_zero));

	/* If it is happened, kill a kernel after print out some useful
	 * information for debugging.
	 */
	debug_log_syscall_exit(idx, entry);
	if (bad_happened)
		BUG();

	entry->exit_time = ktime_get();

	/* Don't return an error code in this function. If this function
	 * fails, just kill a kernel.
	 */
}

struct syscall_logger_ops __logger_ops = {
    .log_syscall_enter = syscall_logger_log_syscall_enter,
    .log_syscall_exit = syscall_logger_log_syscall_exit,
};

module_init(syscall_logger_init);
module_exit(syscall_logger_exit);
