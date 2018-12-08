#ifndef __DEBUG_H
#define __DEBUG_H

void debug_init(void);
void debug_exit(void);

void __repro_debug(const char *fmt, ...);
#define repro_debug(fmt, ...) __repro_debug(fmt, ##__VA_ARGS__);

#endif /* __DEBUG_H */
