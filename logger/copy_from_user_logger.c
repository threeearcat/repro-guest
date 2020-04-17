#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/compiler.h>
#include <linux/copy_from_user_logger.h>

#include "copy_from_user_buffer.h"

DEFINE_PER_CPU(struct copy_from_user_log, copy_from_user_log);
DEFINE_PER_CPU(struct copy_from_user_log, copy_to_user_log);

struct copy_from_user_logger_ops __cfu_ops;
extern struct copy_from_user_logger_ops *copy_from_user_logger_ops;

static void record_copy_from_user(void *to, const void *from, unsigned long n, bool dump_data)
{
    char buf[2048];
    unsigned char *data = to;
    int off, i;
 
    off = sprintf(buf, "CFU %lx -> %lx %ld", (unsigned long)from, (unsigned long)to, n);
    if (dump_data) {
        for (i = 0; i < n; i++)
            off += sprintf(buf+off, " %d", data[i]);
    }
    trace_printk("%s\n", buf);
}

static void record_copy_to_user(void *to, const void *from, unsigned long n, bool dump_data)
{
    char buf[2048];
    unsigned char *data = from;
    int off, i;
 
    off = sprintf(buf, "CTU %lx -> %lx %ld", (unsigned long)from, (unsigned long)to, n);
    if (dump_data) {
        for (i = 0; i < n; i++)
            off += sprintf(buf+off, " %d", data[i]);
    }
    trace_printk("%s\n", buf);
}

int copy_from_user_logger_init(void)
{
	int cpu;
	struct copy_from_user_log *log;
	void *buf;

	for_each_possible_cpu(cpu) {
		log = &per_cpu(copy_from_user_log, cpu);
		buf = kzalloc(CFU_BUFFER_SIZE, GFP_KERNEL);
		log->buf = buf;
		log->idx = 0;
	}

	for_each_possible_cpu(cpu) {
		log = &per_cpu(copy_to_user_log, cpu);
		buf = kzalloc(CFU_BUFFER_SIZE, GFP_KERNEL);
		log->buf = buf;
		log->idx = 0;
	}

	copy_from_user_logger_ops = &__cfu_ops;

	return 0;
}

void copy_from_user_logger_exit(void)
{
	int cpu;
	struct copy_from_user_log *log;
	void *buf;

	copy_from_user_logger_ops = NULL;
	for_each_possible_cpu(cpu) {
		log = &per_cpu(copy_from_user_log, cpu);
		buf = log->buf;
		kfree(buf);
	}

	for_each_possible_cpu(cpu) {
		log = &per_cpu(copy_to_user_log, cpu);
		buf = log->buf;
		kfree(buf);
	}
}

struct copy_from_user_logger_ops __cfu_ops = {
    .record_copy_from_user = record_copy_from_user,
	.record_copy_to_user = record_copy_to_user,
};
