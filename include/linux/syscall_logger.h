#ifndef __SYSCALL_LOGGER_H
#define __SYSCALL_LOGGER_H

struct syscall_logger_ops {
	void (*log_syscall_enter)(unsigned long nr, const struct pt_regs *regs,
									   unsigned long *idxp, unsigned long *cpup);
	void (*log_syscall_exit)(unsigned long idx, unsigned long cpu);
};

extern struct syscall_logger_ops *syscall_logger_ops;

#endif /* __SYSCALL_LOGGER_H */
