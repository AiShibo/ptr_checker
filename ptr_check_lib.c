#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>
#include <md5.h>
#include "ptr_check_lib.h"

typedef struct vm_region {
	struct vm_region *next;
	uint64_t start;
	uint64_t end;
} vm_region;

typedef struct md5_skip_entry {
	struct md5_skip_entry *next;
	unsigned char md5[MD5_DIGEST_LENGTH];
} md5_skip_entry;

vm_region *proc_vm = NULL;
md5_skip_entry *skip_list = NULL;

int get_vm(void) {
	struct procstat *ps;

	struct kinfo_proc *kp;
	unsigned int kp_cnt;

	struct kinfo_vmentry *vm;
	unsigned int vm_cnt;

	unsigned int i;
	vm_region *region;
	vm_region *end_region = NULL;

	ps = procstat_open_sysctl();
	if (!ps)
		return -1;

	kp = procstat_getprocs(ps, KERN_PROC_PID, getpid(), &kp_cnt);
	if (!kp || kp_cnt == 0) {
		procstat_close(ps);
		return -2;
	}

	vm = procstat_getvmmap(ps, kp, &vm_cnt);
	if (!vm) {
		procstat_freeprocs(ps, kp);
		procstat_close(ps);
		return -3;
	}

	for (i = 0; i < vm_cnt; ++i) {
		region = malloc(sizeof(*region));
		memset(region, 0, sizeof(*region));

		region->start = vm[i].kve_start;
		region->end = vm[i].kve_end;

		if (proc_vm == NULL) {
			proc_vm = region;
			end_region = region;
		} else {
			end_region->next = region;
			end_region = region;
		}
	}

	procstat_freevmmap(ps, vm);
	procstat_freeprocs(ps, kp);
	procstat_close(ps);

	return 0;
}

int free_vm(void) {
	while (proc_vm != NULL) {
		vm_region *next = proc_vm->next;
		free(proc_vm);
		proc_vm = next;
	}
	return 0;
}

void print_vm(void) {
	/*
	if (proc_vm == NULL)
		return;

	vm_region *region = proc_vm;
	unsigned int count = 0;

	while (region != NULL) {
		printf("vm region %u has a range %lu --- %lu\n", count, region->start, region->end);
		region = region->next;
		++count;
	}
	*/
}

void compute_md5(const void *data, size_t size, unsigned char *out_md5) {
	MD5_CTX ctx;
	MD5Init(&ctx);
	MD5Update(&ctx, data, size);
	MD5Final(out_md5, &ctx);
}

#ifdef DEBUG_PTR_CHECK
void print_md5(const unsigned char *md5) {
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02x", md5[i]);
	}
}
#endif

int check_skip_list(const unsigned char *md5) {
	md5_skip_entry *current = skip_list;

#ifdef DEBUG_PTR_CHECK
	printf("[DEBUG]     check_skip_list called, skip_list=%p, its location is %p\n", (void*)skip_list, &skip_list);
	int entry_count = 0;
#endif

	while (current != NULL) {
#ifdef DEBUG_PTR_CHECK
		printf("[DEBUG]     Checking entry %d: ", entry_count);
		print_md5(current->md5);
		printf(" vs ");
		print_md5(md5);
		int cmp_result = memcmp(current->md5, md5, MD5_DIGEST_LENGTH);
		printf(" -> memcmp=%d\n", cmp_result);
		entry_count++;
#endif
		if (memcmp(current->md5, md5, MD5_DIGEST_LENGTH) == 0) {
			// Found a match, keep it in the list (don't remove)
#ifdef DEBUG_PTR_CHECK
			printf("[DEBUG]     MATCH FOUND! Keeping entry in skip list\n");
#endif
			return 1; // Skip this check
		}
		current = current->next;
	}

#ifdef DEBUG_PTR_CHECK
	printf("[DEBUG]     No match found in skip list (checked %d entries)\n", entry_count);
#endif
	return 0; // Don't skip
}

int should_skip_check(const void *data, size_t size) {
	unsigned char md5[MD5_DIGEST_LENGTH];
	unsigned char md5_offset16[MD5_DIGEST_LENGTH];

	if (size == 0 || size == 16)
		return 1;

#ifdef DEBUG_PTR_CHECK
	printf("[DEBUG] Checking if should skip: size=%zu\n", size);
	if (size == 3823) {
		printf("this is the interesting one! skip list address is %p\n", &skip_list);
	}
#endif

	// Check MD5 starting at offset 0
	compute_md5(data, size, md5);
#ifdef DEBUG_PTR_CHECK
	printf("[DEBUG]   MD5 at offset 0: ");
	print_md5(md5);
	printf("\n");
#endif
	if (check_skip_list(md5)) {
#ifdef DEBUG_PTR_CHECK
		printf("[DEBUG]   SKIP: Matched at offset 0\n");
#endif
		return 1;
	}

	// Check MD5 starting at offset 16 (for imsg header)
	if (size > 16) {
		compute_md5((const unsigned char *)data + 16, size - 16, md5_offset16);
#ifdef DEBUG_PTR_CHECK
		printf("[DEBUG]   MD5 at offset 16: ");
		print_md5(md5_offset16);
		printf("\n");
#endif
		if (check_skip_list(md5_offset16)) {
#ifdef DEBUG_PTR_CHECK
			printf("[DEBUG]   SKIP: Matched at offset 16\n");
#endif
			return 1;
		}
	}

#ifdef DEBUG_PTR_CHECK
	printf("[DEBUG]   NO SKIP: No match found\n");
#endif
	return 0;
}

void ptr_check_skip(const void *data, size_t size) {
	unsigned char md5[MD5_DIGEST_LENGTH];
	unsigned char md5_offset16[MD5_DIGEST_LENGTH];

	// Compute MD5 at offset 0
	compute_md5(data, size, md5);

	// Check if MD5 at offset 0 already exists
	if (check_skip_list(md5)) {
#ifdef DEBUG_PTR_CHECK
		printf("[DEBUG] Not adding to skip list: MD5 at offset 0 already exists\n");
#endif
		return;
	}

	// Check MD5 at offset 16 if size allows
	// if (size > 16) {
	if (0) {
		compute_md5((const unsigned char *)data + 16, size - 16, md5_offset16);

		// Check if MD5 at offset 16 already exists
		if (check_skip_list(md5_offset16)) {
#ifdef DEBUG_PTR_CHECK
			printf("[DEBUG] Not adding to skip list: MD5 at offset 16 already exists\n");
#endif
			return;
		}
	}

	// No overlap found, add new entry
	md5_skip_entry *entry = malloc(sizeof(*entry));
	if (!entry) {
		return;
	}

	memset(entry, 0, sizeof(*entry));
	memcpy(entry->md5, md5, MD5_DIGEST_LENGTH);

#ifdef DEBUG_PTR_CHECK
	// Count skip list length
	int list_len = 0;
	md5_skip_entry *counter = skip_list;
	while (counter != NULL) {
		list_len++;
		counter = counter->next;
	}

	printf("[DEBUG] Adding to skip list: size=%zu, MD5=", size);
	print_md5(entry->md5);
	printf(", skip_list_length_after_add=%d\n", list_len + 1);
	fflush(stdout);
#endif

	// Add to the beginning of the skip list
	entry->next = skip_list;
	skip_list = entry;
	printf("skip_list is %p. its address is %p\n", skip_list, &skip_list);
	fflush(stdout);
}

void check_pointers(const void *data, size_t size) {
	int get_vm_ret;

	// Check if this message should be skipped
	if (should_skip_check(data, size)) {
		return;
	}

	if (proc_vm != NULL) {
		printf("proc_vm is not NULL!!!\n");
		raise(SIGBUS);
	}

	if ((get_vm_ret = get_vm()) < 0) {
		printf("get_vm() call failed!!!!!, returned value %d\n", get_vm_ret);
		raise(SIGBUS);
	}

	const unsigned char *bytes = (const unsigned char *)data;
	size_t i;
	for (i = 0; i + sizeof(uint64_t) - 1 < size; i++) {
		uint64_t potential_ptr = *(uint64_t *)(bytes + i);

		vm_region *region = proc_vm;
		while (region != NULL) {
			if (potential_ptr >= region->start && potential_ptr < region->end) {
				printf("POINTER DETECTED at offset %zu: 0x%lx (in region %lx-%lx), message size iis %zu\n",
				       i, potential_ptr, region->start, region->end, size);
				free_vm();
				raise(SIGBUS);
			}
			region = region->next;
		}
	}

	free_vm();
}

void check_pointers_with_vm_print(const void *data, size_t size) {
	int get_vm_ret;

	// Check if this message should be skipped
	if (should_skip_check(data, size)) {
		return;
	}

	if (proc_vm != NULL) {
		printf("proc_vm is not NULL!!!\n");
		raise(SIGBUS);
	}

	if ((get_vm_ret = get_vm()) < 0) {
		printf("get_vm() call failed!!!!!, returned value %d\n", get_vm_ret);
		raise(SIGBUS);
	}

	print_vm();

	const unsigned char *bytes = (const unsigned char *)data;
	size_t i;
	for (i = 0; i + sizeof(uint64_t) - 1 < size; i++) {
		uint64_t potential_ptr = *(uint64_t *)(bytes + i);

		vm_region *region = proc_vm;
		while (region != NULL) {
			if (potential_ptr >= region->start && potential_ptr < region->end) {
				printf("POINTER DETECTED at offset %zu: 0x%lx (in region %lx-%lx), message size iis %zu\n",
				       i, potential_ptr, region->start, region->end, size);
				free_vm();
				raise(SIGBUS);
			}
			region = region->next;
		}
	}

	free_vm();
}
