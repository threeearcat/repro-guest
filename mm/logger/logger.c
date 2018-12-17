#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/audit.h>

#include <linux/syscall_logger.h>

#include "buffer.h"
#include "proc.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dae R. Jeong");

DEFINE_PER_CPU(struct syscall_log, syscall_log);

struct syscall_logger_ops __logger_ops;

static void destroy_log_buffer(void)
{
	int cpu;
	struct syscall_log *log;

	for_each_possible_cpu(cpu) {
		log = &per_cpu(syscall_log, cpu);
		kfree(log->buf);
#ifdef CONFIG_SYSCALL_LOGGER_LOG_STATISTICS
		kfree(log->stats);
#endif
	}
}

static int create_log_buffer(void)
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

	return 0;

 mem_alloc_failed:
	repro_debug("Mem allocation failed");
	destroy_log_buffer();

	return -ENOMEM;
}

static int __init syscall_logger_init(void)
{
	int ret;
	/* Create per-CPU log buffer first */
	ret = create_log_buffer();

	/* Now per-cpu ring buffers are made up and we can log
	 * syscalls. Let's allow syscall entry to call logger functions.
	 */
	syscall_logger_ops = &__logger_ops;

	syscall_logger_proc_init();

	debug_init();

	return ret;
}

static void __exit syscall_logger_exit(void)
{
	debug_exit();

	syscall_logger_proc_exit();

	/* disallow syscall entry to call logger functions first */
	syscall_logger_ops = NULL;

	/* TODO: It is possible that other CPUs are still logging
	 * syscalls. Wait until they finish their jobs.
	 */

	/* Now we can destroy log buffer */
	destroy_log_buffer();
}

/* Should be called with allocated entry */
static struct syscall_log_entry * syscall_logger_log_syscall_enter(unsigned long nr, const struct pt_regs *regs)
{
	struct syscall_log *log;
	struct syscall_log_entry *entry;
	unsigned long idx, flags;
	// .tv64 is a signed variable
	ktime_t ktime_max = { .tv64 = -1 };

	/* Retrieving idx. local IRQ should be disabled here in order to
	 * avoid a race on idx.
	 */
	local_irq_save(flags);
	log = &per_cpu(syscall_log, smp_processor_id());
	idx = log->idx;
	log->idx = (idx + 1) & MAX_ENTRY_MASK;
	local_irq_restore(flags);

	/* Get the address of the corresponding entry. */
	entry = ((struct syscall_log_entry *)(log->buf) + idx);

	/* See do_syscall_64(). */
	entry->nr = nr;
	entry->rdi = regs->di;
	entry->rsi = regs->si;
	entry->rdx = regs->dx;
	entry->r10 = regs->r10;
	entry->r8 = regs->r8;
	entry->r9 = regs->r9;

	/* Log entry_time first. exit_time will be logged later. */
	/* Ref of ktime_get() vs do_gettimeofday():
	 * https://lore.kernel.org/patchwork/patch/847639/
	 */
	entry->entry_time = ktime_get();
	/* Assign ktime_max to exit_time to handle the situation that a
	 * kernel dies before this syscall return
	 */
	entry->exit_time = ktime_max;

#ifdef CONFIG_SYSCALL_LOGGER_LOG_STATISTICS
	/* Increase an execution number to record statistics. */
	(log->stats)[entry->nr]++;
#endif

	debug_log_syscall_enter(entry);

	/* It is possible that a syscall is migrated by a scheduler during
	 * its execution. Is this important to our research project? Does
	 * this give any fun chance to make things difficult?
	 */

	return entry;
}

static void syscall_logger_log_syscall_exit(struct syscall_log_entry *entry)
{
	ktime_t ktime_max = { .tv64 = -1 };

	// Another syscall writes exit_time before this syscall release
	// this entry. Print some useful information and panic.
	bool bad_happened = ktime_compare(entry->exit_time, ktime_max);

	debug_log_syscall_exit(entry);

	if (bad_happened)
		BUG();

	/* Write exit_time. Now we have the full-filled entry */
	entry->exit_time = ktime_get();
}

struct syscall_logger_ops __logger_ops = {
    .log_syscall_enter = syscall_logger_log_syscall_enter,
    .log_syscall_exit = syscall_logger_log_syscall_exit,
};

module_init(syscall_logger_init);
module_exit(syscall_logger_exit);
