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

	/* Timestamps on entry/exit */
	ktime_t entry_time;
	ktime_t exit_time;

	/* TODO: Is there any automatic way to calculate the pad and to
	 * specify the alignment? Do I need to remove pad?
	 */
	char pad[56];
} __attribute__ ((__aligned__(128)));

struct syscall_logger_ops {
	void (*log_syscall_enter)(unsigned long nr, const struct pt_regs *regs,
							  struct syscall_log_entry *entry);
	void (*log_syscall_exit)(struct syscall_log_entry *entry);
};

extern struct syscall_logger_ops *syscall_logger_ops;

#endif /* __SYSCALL_LOGGER_H */
