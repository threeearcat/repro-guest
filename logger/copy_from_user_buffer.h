#ifndef __COPY_FROM_USER_BUFFER_H
#define __COPY_FROM_USER_BUFFER_H

#define CFU_BUFFER_SIZE (1 << 12) << 10

struct copy_from_user_log {
	void *buf;
	unsigned long idx;
};

struct copy_from_user_entry {
	void *to;
	void *from;
	unsigned long n;
	void *value;
	char *name;
};

DECLARE_PER_CPU(struct copy_from_user_log, copy_from_user_log);

#endif /* __COPY_FROM_USER_BUFFER_H */
