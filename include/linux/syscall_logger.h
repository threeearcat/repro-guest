#ifndef __SYSCALL_LOGGER_H
#define __SYSCALL_LOGGER_H

struct syscall_logger_ops {
	int (*log_one_syscall)(unsigned long nr, const struct pt_regs *regs);
};

extern struct syscall_logger_ops *syscall_logger_ops;

#endif /* __SYSCALL_LOGGER_H */
