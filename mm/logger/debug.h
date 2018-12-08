#ifndef __DEBUG_H
#define __DEBUG_H

void debug_syscall_logger_init(void);
void debug_after_syscall_logger_init(void);
void debug_syscall_logger_exit(void);
void __repro_debug(const char *fmt, ...);

#define repro_debug(fmt, ...) __repro_debug(fmt, ##__VA_ARGS__);

#endif /* __DEBUG_H */
