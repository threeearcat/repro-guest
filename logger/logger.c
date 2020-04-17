#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/audit.h>

#include <linux/syscall_logger.h>

#include "syscall_buffer.h"
#include "proc.h"
#include "copy_from_user_logger.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dae R. Jeong");

DEFINE_PER_CPU(struct syscall_log, syscall_log);

struct syscall_logger_ops __logger_ops;

struct copy_from_user_logger_ops *copy_from_user_logger_ops = NULL;
EXPORT_SYMBOL(copy_from_user_logger_ops);

static spinlock_t entry_lock;

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
		buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
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

static int syscall_logger_init(void)
{
	int ret;
#ifdef CONFIG_COPY_FROM_USER_LOGGER	
	ret = copy_from_user_logger_init();
	if (ret)
		return ret;
#endif
	/* Create per-CPU log buffer first */
	ret = create_log_buffer();
	spin_lock_init(&entry_lock);

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

#ifdef CONFIG_COPY_FROM_USER_LOGGER
	copy_from_user_logger_exit();
#endif
}

/* Should be called with allocated entry */
static struct syscall_log_entry * syscall_logger_log_syscall_enter(unsigned long nr, const struct pt_regs *regs)
{
    return NULL;
}

static void syscall_logger_log_syscall_exit(struct syscall_log_entry *entry, unsigned long ret)
{
}

#ifdef CONFIG_COPY_FROM_USER_LOGGER
extern void record_copy_from_user(void *to, const void *from, unsigned long n, bool dump_write);
#else
void record_copy_from_user(void *to, const void *from, unsigned long n, bool dump_write)
{
}
#endif

struct syscall_logger_ops __logger_ops = {
    .log_syscall_enter = syscall_logger_log_syscall_enter,
    .log_syscall_exit = syscall_logger_log_syscall_exit,
};

module_init(syscall_logger_init);
module_exit(syscall_logger_exit);
