#ifndef __BUFFER_H
#define __BUFFER_H

#include <linux/ktime.h>
#include "debug.h"

#ifdef CONFIG_X86_64

/* per-CPU logger state */
struct syscall_log {
	void *buf;
	unsigned long idx;
#ifdef CONFIG_SYSCALL_LOGGER_LOG_STATISTICS
	/* Statistics for each syscalls */
	unsigned int *stats;
#endif
};

struct syscall_log_entry {
	/* Syscall number */
	unsigned long nr;

	/* Syscall arguments. See do_syscall_64 */
	unsigned long rdi;
	unsigned long rsi;
	unsigned long rdx;
	unsigned long r10;
	unsigned long r8;
	unsigned long r9;

	/* Timestamps on entry/exit */
	ktime_t entry_time;
	ktime_t exit_time;

	/* TODO: Is there any automatic way to calculate the pad and to
	 * specify the alignment? Do I need to remove pad?
	 */
	char pad[56];
} __attribute__ ((__aligned__(128)));

#define ENTRY_SIZE_BITS 7
#define ENTRY_SIZE sizeof(struct syscall_log_entry)

#define NR_BUFFER_PAGE 1024
#define BUFFER_SIZE (PAGE_SIZE * NR_BUFFER_PAGE)

#define NR_MAX_ENTRY ((NR_BUFFER_PAGE * PAGE_SIZE) >> (ENTRY_SIZE_BITS))
#define MAX_ENTRY_MASK (NR_MAX_ENTRY - 1)

DECLARE_PER_CPU(struct syscall_log, syscall_log);

#else
/* Current implementation supports only x86_64. Abort compilation. */
/* TODO: What is the statement that I can use in a header file? */
BUILD_BUG_ON("Not supported architecture");
#endif /* CONFIG_X86_64 */

#endif /* __BUFFER_H */
