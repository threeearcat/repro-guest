#ifndef __COPY_FROM_USER_BUFFER_H
#define __COPY_FROM_USER_BUFFER_H

#define CFU_BUFFER_PAGE 10
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
	char *name;
	unsigned long timestamp;

	char pad[15];
	char occupied;

#define DATA_SIZE 192
	char data[DATA_SIZE];
} __attribute__ ((aligned(256)));

#define NR_CFU_INDEX (CFU_BUFFER_SIZE / sizeof(struct copy_from_user_entry))
#define CFU_INDEX_MASK (NR_CFU_INDEX - 1)

DECLARE_PER_CPU(struct copy_from_user_log, copy_from_user_log);

#endif /* __COPY_FROM_USER_BUFFER_H */
