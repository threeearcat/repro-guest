#define pr_fmt(fmt) "Repro: " fmt

#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>

#include "syscall_buffer.h"

__printf(1, 2)
void __repro_debug(const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	pr_err("%pV\n", &vaf);

	va_end(args);
}

#ifdef CONFIG_DEBUG_SYSCALL_LOGGER

static DEFINE_SPINLOCK(debug_spinlock);

void debug_init(void)
{
	int cpu;
	struct syscall_log *log;

	/* Print out macro values */
	pr_info("ENTRY_SIZE:          %lu\n", ENTRY_SIZE);
	pr_info("ENTRY_SIZE_BITS:     %d\n", ENTRY_SIZE_BITS);
	pr_info("NR_BUFFER_PAGE:      %d\n", NR_BUFFER_PAGE);
	pr_info("BUFFER_SIZE:         %lx\n", BUFFER_SIZE);
	pr_info("NR_MAX_ENTRY:        %lu\n", NR_MAX_ENTRY);
	pr_info("MAX_ENTRY_MASK:      %lx\n", MAX_ENTRY_MASK);

	/* Print out addresses of each of buffer pages */
	for_each_possible_cpu(cpu) {
		log = &per_cpu(syscall_log, cpu);

		pr_info("CPU #%d:\n", cpu);
		pr_info("    buf:             %p\n", log->buf);
#ifdef CONFIG_SYSCALL_LOGGER_LOG_STATISTICS
		pr_info("    stats:           %p\n", log->stats);
#endif
	}
}

void debug_exit(void)
{
}

static void print_entry(struct syscall_log_entry *entry)
{
	pr_info("  Entry addr:    %p\n", entry);
	pr_info("    INUSE :      %d\n", entry->inuse);
	pr_info("    NR    :      %lu\n", entry->nr);
	pr_info("    RDI   :      %lu\n", entry->rdi);
	pr_info("    RSI   :      %lu\n", entry->rsi);
	pr_info("    RDX   :      %lu\n", entry->rdx);
	pr_info("    R10   :      %lu\n", entry->r10);
	pr_info("    R8    :      %lu\n", entry->r8);
	pr_info("    R9    :      %lu\n", entry->r9);
	pr_info("    EnTime:      %lld\n", entry->entry_time.tv64);
	pr_info("    ExTime:      %lld\n", entry->exit_time.tv64);

}

void debug_log_syscall_enter(struct syscall_log_entry *entry)
{
	int cpu = get_cpu();
	spin_lock(&debug_spinlock);
	pr_info("CPU #%d:         syscall_enter\n", cpu());
	print_entry(entry);
	spin_unlock(&debug_spinlock);
	put_cpu();
}

void debug_log_syscall_exit(struct syscall_log_entry *entry)
{
	int cpu = get_cpu();
	spin_lock(&debug_spinlock);
	pr_info("CPU #%d:         syscall_exit\n", cpu);
	print_entry(entry);
	spin_unlock(&debug_spinlock);
	put_cpu();
}
#else
void debug_init(void)
{
}

void debug_exit(void)
{
}

void debug_log_syscall_enter(struct syscall_log_entry *entry)
{
}

void debug_log_syscall_exit(struct syscall_log_entry *entry)
{
}
#endif /* CONFIG_DEBUG_SYSCALL_LOGGER */
