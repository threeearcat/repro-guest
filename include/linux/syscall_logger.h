#ifndef __SYSCALL_LOGGER_H
#define __SYSCALL_LOGGER_H

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

	unsigned long ret;

	/* Timestamps on entry/exit */
	unsigned long entry_time;
	unsigned long exit_time;

	/* TODO: Is there any automatic way to calculate the pad and to
	 * specify the alignment? Do I need to remove pad?
	 */
	char pad[16];
	unsigned long skipped;

	// We have a lot of space. make pid and tid 8-byte-aligned.
	unsigned long pid;
	unsigned long tid;

	// A syscall occupies this entry
	// Entry is large enough. Make it 8-byte aligned.
	unsigned long inuse;
} __attribute__ ((__aligned__(128)));

struct syscall_logger_ops {
	struct syscall_log_entry * (*log_syscall_enter)(unsigned long nr, const struct pt_regs *regs);
	void (*log_syscall_exit)(struct syscall_log_entry *entry, unsigned long ret);
};

extern struct syscall_logger_ops *syscall_logger_ops;

#endif /* __SYSCALL_LOGGER_H */
