#ifndef __BUFFER_H
#define __BUFFER_H

#include <linux/ktime.h>
#include <linux/syscall_logger.h>
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

#define ENTRY_SIZE_BITS 7
#define ENTRY_SIZE sizeof(struct syscall_log_entry)

// I want to extract the number of buffer pages from binary. I think
// there is a beautiful way to do this, but the below is ugly. Anyway,
// this is convinient :). I can just do "strings vmlinux | grep
// BUFFER_PAGE=".
#define __BUFFER_PAGE(N)												\
	static const int NR_BUFFER_PAGE=N;									\
	static char __attribute__((used)) *buffer_size="SYSCALL_BUFFER_PAGE="#N; \

#ifdef CONFIG_SYSCALL_LOGGER_LARGE_BUFFER
__BUFFER_PAGE(1024)
#else
// For debug purpose
__BUFFER_PAGE(1)
#endif
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
