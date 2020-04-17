#include <linux/kernel.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE0(mark_entry) {
    trace_printk("ENTRY\n");
    return 0;
}

SYSCALL_DEFINE0(mark_exit) {
    trace_printk("EXIT\n");
    return 0;
}
