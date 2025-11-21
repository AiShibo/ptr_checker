#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>
#include <md5.h>
#include "buffer_check_lib.h"

static void debug_print(int indent_level, const char *format, ...) {
	return;
	va_list args;
	printf("[DEBUG] ");
	for (int i = 0; i < indent_level; i++) {
		printf("    ");
	}
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

// Declare msan function as weak symbol - will be resolved at link time if available
extern long __msan_test_shadow(const void *p, size_t n) __attribute__((weak));

// Helper function to safely call msan if available
static long safe_msan_test_shadow(const void *p, size_t n) {
	long return_val;

	if (__msan_test_shadow) {
		return_val = __msan_test_shadow(p, n);
		debug_print(0, "msan check result is %ld\n", return_val);
		return return_val;
	}
	return -1;  // No msan available, return -1 (no uninitialized memory detected)
}

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

void compute_md5(const void *data, size_t size, unsigned char *out_md5) {
	MD5_CTX ctx;
	MD5Init(&ctx);
	MD5Update(&ctx, data, size);
	MD5Final(out_md5, &ctx);
}

static void print_md5(const unsigned char *md5) {
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02x", md5[i]);
	}
}

int check_skip_list(const unsigned char *md5) {
	md5_skip_entry *current = skip_list;
	int entry_count = 0;

	debug_print(1, "check_skip_list called, skip_list=%p, its location is %p\n", (void*)skip_list, &skip_list);

	while (current != NULL) {
		debug_print(1, "Checking entry %d: ", entry_count);
		print_md5(current->md5);
		debug_print(0, " vs ");
		print_md5(md5);
		debug_print(0, " -> memcmp=%d\n", memcmp(current->md5, md5, MD5_DIGEST_LENGTH));
		entry_count++;

		if (memcmp(current->md5, md5, MD5_DIGEST_LENGTH) == 0) {
			// Found a match, keep it in the list (don't remove)
			debug_print(1, "MATCH FOUND! Keeping entry in skip list\n");
			return 1; // Skip this check
		}
		current = current->next;
	}

	debug_print(1, "No match found in skip list (checked %d entries)\n", entry_count);
	return 0; // Don't skip
}

int should_skip_check(const void *data, size_t size) {
	unsigned char md5[MD5_DIGEST_LENGTH];

	// Temp disable all ptr checks
	// return 1;


	if (size == 0)
		return 1;

	debug_print(0, "Checking if should skip: size=%zu\n", size);
	if (size == 3823) {
		debug_print(0, "this is the interesting one! skip list address is %p\n", &skip_list);
	}

	// Check MD5 starting at offset 0
	compute_md5(data, size, md5);
	debug_print(0, "  MD5 at offset 0: ");
	print_md5(md5);
	debug_print(0, "\n");

	if (check_skip_list(md5)) {
		debug_print(0, "  SKIP: Matched at offset 0\n");
		return 1;
	}

	debug_print(0, "  NO SKIP: No match found\n");
	return 0;
}

void ptr_check_skip(const void *data, size_t size) {
	unsigned char md5[MD5_DIGEST_LENGTH];

	// Compute MD5 at offset 0
	compute_md5(data, size, md5);

	// Check if MD5 at offset 0 already exists
	if (check_skip_list(md5)) {
		debug_print(0, "Not adding to skip list: MD5 at offset 0 already exists\n");
		return;
	}

	// No overlap found, add new entry
	md5_skip_entry *entry = malloc(sizeof(*entry));
	if (!entry) {
		return;
	}

	memset(entry, 0, sizeof(*entry));
	memcpy(entry->md5, md5, MD5_DIGEST_LENGTH);

	// Count skip list length
	int list_len = 0;
	md5_skip_entry *counter = skip_list;
	while (counter != NULL) {
		list_len++;
		counter = counter->next;
	}

	debug_print(0, "Adding to skip list: size=%zu, MD5=", size);
	print_md5(entry->md5);
	debug_print(0, ", skip_list_length_after_add=%d\n", list_len + 1);

	// Add to the beginning of the skip list
	entry->next = skip_list;
	skip_list = entry;
	debug_print(0, "skip_list is %p. its address is %p\n", skip_list, &skip_list);
}

void check_pointers(const void *data, size_t size) {
	int get_vm_ret;

	if (data == NULL)
		return;

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
				printf("POINTER DETECTED in memory location %p at offset %zu with value 0x%lx (in region %lx-%lx), message size iis %zu\n",
				       (uint64_t *)(bytes + i), i, potential_ptr, region->start, region->end, size);
				free_vm();
				raise(SIGBUS);
			}
			region = region->next;
		}
	}

	free_vm();
}

void check_buffer_with_msan(const void *data, size_t size) {
	int unint_location;

	if ((unint_location = safe_msan_test_shadow(data, size)) != -1) {
		printf("Buffer contains uninitialized memory! message len is %zu, unint location is %d\n", size, unint_location);
		raise(SIGBUS);
	}
}

void check_buffer(const void *data, size_t size) {
#ifdef ENABLE_MSAN_CHECK
	check_buffer_with_msan(data, size);
#endif

#ifdef ENABLE_PTR_CHECK
	check_pointers(data, size);
#endif

#if !defined(ENABLE_MSAN_CHECK) && !defined(ENABLE_PTR_CHECK)
	(void)data;
	(void)size;
#endif
}
