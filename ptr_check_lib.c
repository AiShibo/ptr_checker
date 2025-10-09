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
#include "ptr_check_lib.h"

typedef struct vm_region {
	struct vm_region *next;
	uint64_t start;
	uint64_t end;
} vm_region;

static vm_region *proc_vm = NULL;

static int get_vm(void) {
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

static int free_vm(void) {
	while (proc_vm != NULL) {
		vm_region *next = proc_vm->next;
		free(proc_vm);
		proc_vm = next;
	}
	return 0;
}

static void print_vm(void) {
	if (proc_vm == NULL)
		return;

	vm_region *region = proc_vm;
	unsigned int count = 0;

	while (region != NULL) {
		printf("vm region %u has a range %lu --- %lu\n", count, region->start, region->end);
		region = region->next;
		++count;
	}
}

void check_pointers(const void *data, size_t size) {
	int get_vm_ret;

	if (proc_vm != NULL) {
		printf("proc_vm is not NULL!!!\n");
		raise(SIGSEGV);
	}

	if ((get_vm_ret = get_vm()) < 0) {
		printf("get_vm() call failed!!!!!, returned value %d\n", get_vm_ret);
		raise(SIGSEGV);
	}

	const unsigned char *bytes = (const unsigned char *)data;
	size_t i;
	for (i = 0; i + sizeof(uint64_t) - 1 < size; i++) {
		uint64_t potential_ptr = *(uint64_t *)(bytes + i);

		vm_region *region = proc_vm;
		while (region != NULL) {
			if (potential_ptr >= region->start && potential_ptr < region->end) {
				printf("POINTER DETECTED at offset %zu: 0x%lx (in region %lu-%lu)\n",
				       i, potential_ptr, region->start, region->end);
				free_vm();
				raise(SIGSEGV);
			}
			region = region->next;
		}
	}

	free_vm();
}

void check_pointers_with_vm_print(const void *data, size_t size) {
	int get_vm_ret;

	if (proc_vm != NULL) {
		printf("proc_vm is not NULL!!!\n");
		raise(SIGSEGV);
	}

	if ((get_vm_ret = get_vm()) < 0) {
		printf("get_vm() call failed!!!!!, returned value %d\n", get_vm_ret);
		raise(SIGSEGV);
	}

	print_vm();

	const unsigned char *bytes = (const unsigned char *)data;
	size_t i;
	for (i = 0; i + sizeof(uint64_t) - 1 < size; i++) {
		uint64_t potential_ptr = *(uint64_t *)(bytes + i);

		vm_region *region = proc_vm;
		while (region != NULL) {
			if (potential_ptr >= region->start && potential_ptr < region->end) {
				printf("POINTER DETECTED at offset %zu: 0x%lx (in region %lu-%lu)\n",
				       i, potential_ptr, region->start, region->end);
				free_vm();
				raise(SIGSEGV);
			}
			region = region->next;
		}
	}

	free_vm();
}
