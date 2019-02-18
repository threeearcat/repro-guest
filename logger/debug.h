#ifndef __DEBUG_H
#define __DEBUG_H

struct syscall_log_entry;

void debug_init(void);
void debug_exit(void);
void debug_log_syscall_enter(struct syscall_log_entry *entry);
void debug_log_syscall_exit(struct syscall_log_entry *entry);

void __repro_debug(const char *fmt, ...);
#define repro_debug(fmt, ...) __repro_debug(fmt, ##__VA_ARGS__);

#endif /* __DEBUG_H */
