#ifndef __COPY_FROM_USER_BUFFER_H
#define __COPY_FROM_USER_BUFFER_H

#define CFU_BUFFER_PAGE 1
#define CFU_BUFFER_SIZE PAGE_SIZE * CFU_BUFFER_PAGE

struct copy_from_user_log {
	void *buf;
	unsigned long idx;
};

// copy_from_user_entry should be power of 2
struct copy_from_user_entry {
	void *to;
	void *from;
	unsigned long n;
	void *value;
	char *name;

	char pad[23];
	char occupied;
} __attribute__ ((aligned(64)));

#define NR_CFU_INDEX (CFU_BUFFER_SIZE / sizeof(struct copy_from_user_entry))
#define CFU_INDEX_MASK (NR_CFU_INDEX - 1)

DECLARE_PER_CPU(struct copy_from_user_log, copy_from_user_log);

#endif /* __COPY_FROM_USER_BUFFER_H */
