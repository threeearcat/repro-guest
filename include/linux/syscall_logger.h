#ifndef __SYSCALL_LOGGER_H
#define __SYSCALL_LOGGER_H

struct syscall_logger_ops {
	unsigned long (*log_one_syscall)(unsigned long nr, const struct pt_regs *regs);
	void (*log_syscall_exit)(unsigned long idx);
};

extern struct syscall_logger_ops *syscall_logger_ops;

#endif /* __SYSCALL_LOGGER_H */
