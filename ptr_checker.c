#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include "ptr_check_lib.h"

ssize_t write(int fd, const void *buf, size_t nbytes) {
	check_pointers_with_vm_print(buf, nbytes);

#if 1
	static ssize_t (*real_write)(int, const void *, size_t) = NULL;
	if (!real_write) {
		real_write = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
	}

	real_write(fd, buf, nbytes);
	return 0;
#else
	return 0;
#endif
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
	if (msg && msg->msg_iov) {
		int iov_idx;
		for (iov_idx = 0; iov_idx < msg->msg_iovlen; iov_idx++) {
			check_pointers_with_vm_print(msg->msg_iov[iov_idx].iov_base,
			                             msg->msg_iov[iov_idx].iov_len);
		}
	}

#if 1
	static ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = NULL;
	if (!real_sendmsg) {
		real_sendmsg = (ssize_t (*)(int, const struct msghdr *, int))dlsym(RTLD_NEXT, "sendmsg");
	}

	real_sendmsg(fd, msg, flags);
	return 0;
#else
	return 0;
#endif
}
