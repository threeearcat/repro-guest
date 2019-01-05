#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/copy_from_user_logger.h>

#include "copy_from_user_buffer.h"

DEFINE_PER_CPU(struct copy_from_user_log, copy_from_user_log);

void record_copy_from_user(void *to, const void *from, unsigned long n)
{
	unsigned long flags, idx;
	struct copy_from_user_entry *entry;
	struct copy_from_user_log *log;
	void *buf;

	local_irq_save(flags);
	log = &per_cpu(copy_from_user_log, smp_processor_id());
	idx = log->idx++;
	local_irq_restore(flags);

	buf = log->buf;
	entry = ((struct copy_from_user_entry *)buf + idx);

	entry->to = to;
	entry->from = from;
	entry->n = n;
	entry->value = kmalloc(n, GFP_KERNEL);
	memcpy(entry->value, to, n);
}
EXPORT_SYMBOL(record_copy_from_user);

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

	return 0;
}

void copy_from_user_logger_exit(void)
{
	// TODO: Free memory
}
