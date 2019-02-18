#ifndef __COPY_FROM_USER_BUFFER_H
#define __COPY_FROM_USER_BUFFER_H

#define __CFU_BUFFER_PAGE(N)											\
	static const int NR_CFU_BUFFER_PAGE=N;								\
	static char __attribute__((used)) *cfu_buffer_size="CFU_BUFFER_PAGE="#N; \

__CFU_BUFFER_PAGE(1024)
#define CFU_BUFFER_SIZE PAGE_SIZE * NR_CFU_BUFFER_PAGE

struct copy_from_user_log {
	void *buf;
	unsigned long idx;
};

// copy_from_user_entry should be power of 2
struct copy_from_user_entry {
	void *to;
	const void *from;
	unsigned long n;
	char *name;
	unsigned long timestamp;
	// No need to have tid
	unsigned long pid;

	char pad[7];
	char occupied;

#define DATA_SIZE 192
	char data[DATA_SIZE];
} __attribute__ ((aligned(256)));

#define NR_CFU_INDEX (CFU_BUFFER_SIZE / sizeof(struct copy_from_user_entry))
#define CFU_INDEX_MASK (NR_CFU_INDEX - 1)

DECLARE_PER_CPU(struct copy_from_user_log, copy_from_user_log);

#endif /* __COPY_FROM_USER_BUFFER_H */
