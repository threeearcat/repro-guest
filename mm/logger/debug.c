#define pr_fmt(fmt) "Repro: " fmt

#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/kernel.h>

#include "buffer.h"

__printf(1, 2)
void __repro_debug(const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	pr_err("%p\n", &vaf);

	va_end(args);
}

#ifdef CONFIG_DEBUG_SYSCALL_LOGGER

void debug_syscall_logger_init(void)
{
	/* Print out macro values */
	pr_info("ENTRY_MASK:      %d\n", ENTRY_MASK);
	pr_info("ENTRY_SIZE:      %lu\n", ENTRY_SIZE);
	pr_info("NR_MAX_ENTRY:    %lu\n", NR_MAX_ENTRY);
	pr_info("NR_BUFFER_PAGE:  %d\n", NR_BUFFER_PAGE);
	pr_info("BUFFER_SIZE:     %lx\n", BUFFER_SIZE);
}

void debug_after_syscall_logger_init(void)
{
	int cpu;

	/* Print out addresses of each of buffer pages */
	for_each_possible_cpu(cpu) {
		pr_info("CPU #%d:          %p\n",
				cpu, per_cpu(rpr_log_buf, cpu));
	}
}

void debug_syscall_logger_exit(void)
{
}
#else
void debug_syscall_logger_init(void)
{
}

void debug_after_syscall_logger_init(void)
{
}

void debug_syscall_logger_exit(void)
{
}
#endif /* CONFIG_DEBUG_SYSCALL_LOGGER */
