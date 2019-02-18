#include <linux/kernel.h>
#include <linux/audit.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include "syscall_buffer.h"

#define PROCFS_NAME 		"syscall_logger"

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *proc_ent;

static int syscall_logger_show_statistics(struct seq_file *f, void *v)
{
	int nr = *(loff_t *)v, cnt = 0, cpu;
	struct syscall_log *log;

	for_each_possible_cpu(cpu) {
		log = &per_cpu(syscall_log, cpu);
		cnt += (log->stats)[nr];
	}

	seq_printf(f, "%d: %d\n", nr, cnt);
	return 0;
}

static void *syscall_logger_seq_start(struct seq_file *f, loff_t *pos)
{
	return (*pos < NR_syscalls) ? pos : NULL;
}

static void *syscall_logger_seq_next(struct seq_file *f, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos >= NR_syscalls)
		return NULL;
	return pos;
}

static void syscall_logger_seq_stop(struct seq_file *f, void *v)
{
	/* Nothing to do */
}

static const struct seq_operations syscall_logger_seq_ops = {
    .start = syscall_logger_seq_start,
	.next  = syscall_logger_seq_next,
	.stop  = syscall_logger_seq_stop,
	.show  = syscall_logger_show_statistics,
};

static int syscall_logger_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &syscall_logger_seq_ops);
}

static struct file_operations syscall_logger_proc_ops =
{
	.owner      = THIS_MODULE,
	.open       = syscall_logger_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = seq_release,
};

int syscall_logger_proc_init(void)
{
	proc_ent = proc_create(PROCFS_NAME, 0444, NULL, &syscall_logger_proc_ops);
	return 0;
}

void syscall_logger_proc_exit(void)
{
	proc_remove(proc_ent);
}
#else
int syscall_logger_proc_init(void)
{
}

void syscall_logger_proc_exit(void)
{
}
#endif /* CONFIG_PROC_FS */
