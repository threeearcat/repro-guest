#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/compiler.h>
#include <linux/copy_from_user_logger.h>

#include "copy_from_user_buffer.h"

DEFINE_PER_CPU(struct copy_from_user_log, copy_from_user_log);

struct copy_from_user_logger_ops __cfu_ops;
extern struct copy_from_user_logger_ops *copy_from_user_logger_ops;

static void record_copy_from_user(void *to, const void *from, unsigned long n, bool dump_data)
{
	unsigned long flags, idx;
	struct copy_from_user_entry *entry;
	struct copy_from_user_log *log;
	void *buf;

	if (n > DATA_SIZE)
		return;

	local_irq_save(flags);
	log = &per_cpu(copy_from_user_log, smp_processor_id());
	idx = log->idx;
	log->idx = (log->idx + 1) & CFU_INDEX_MASK;
	buf = log->buf;
	entry = ((struct copy_from_user_entry *)buf + idx);
	local_irq_restore(flags);

	entry->to = to;
	entry->from = from;
	entry->n = n;
	entry->timestamp = rdtsc();
	// No need to log tid. They have same address space.
	entry->pid = (unsigned long) task_tgid_nr(current);
	entry->occupied = 1;
	if (dump_data)
		memcpy(entry->data, to, n);
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
}

struct copy_from_user_logger_ops __cfu_ops = {
    .record_copy_from_user = record_copy_from_user,
};
