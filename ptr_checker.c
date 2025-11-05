#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include "ptr_check_lib.h"
#include <stdatomic.h>

// Declare msan function as weak symbol - will be resolved at link time if available
extern long __msan_test_shadow(const void *p, size_t n) __attribute__((weak));

// Helper function to safely call msan if available
static long safe_msan_test_shadow(const void *p, size_t n) {
	long return_val;

	if (__msan_test_shadow) {
		return_val =  __msan_test_shadow(p, n);
		printf("msan check result is %d\n", return_val);
		return return_val;
	}
	return -1;  // No msan available, return -1 (no uninitialized memory detected)
}

struct	msgbuf {
#define	MSG_MAGIC	0x063061
	long	msg_magic;		/* [I] buffer magic value */
	long	msg_bufx;		/* [L] write pointer */
	long	msg_bufr;		/* [L] read pointer */
	long	msg_bufs;		/* [I] real msg_bufc size (bytes) */
	long	msg_bufd;		/* [L] number of dropped bytes */
	char	msg_bufc[1];		/* [Lw] buffer */
};

struct imsgbuf {
	struct msgbuf		*w;
	pid_t			 pid;
	uint32_t		 maxsize;
	int			 fd;
	int			 flags;
};

/*
ssize_t write(int fd, const void *buf, size_t nbytes) {
	int unint_location;

	if ((unint_location = safe_msan_test_shadow(buf, nbytes)) != -1) {
		printf("intercepting write, sending a buffer contains unitialized memory! message len is %zu, unint location is %d\n", nbytes, unint_location);
		// raise(SIGBUS);
	}

	check_pointers_with_vm_print(buf, nbytes);

#if 1
	static ssize_t (*real_write)(int, const void *, size_t) = NULL;
	if (!real_write) {
		real_write = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
	}

	return real_write(fd, buf, nbytes);
#else
	return 0;
#endif
}
*/

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
	int unint_location;


	if (msg && msg->msg_iov) {
		int iov_idx;
		for (iov_idx = 0; iov_idx < msg->msg_iovlen; iov_idx++) {
			if ((unint_location = safe_msan_test_shadow(msg->msg_iov[iov_idx].iov_base,
					   msg->msg_iov[iov_idx].iov_len)) != -1) {
				printf("intercepting sendmsg, sending a buffer contains unitialized memory! message len is %zu, unint location is %d\n", msg->msg_iov[iov_idx].iov_len, unint_location);
				// raise(SIGBUS);

			}

			check_pointers_with_vm_print(msg->msg_iov[iov_idx].iov_base,
			                             msg->msg_iov[iov_idx].iov_len);
		}
	}

#if 1
	static ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = NULL;
	if (!real_sendmsg) {
		real_sendmsg = (ssize_t (*)(int, const struct msghdr *, int))dlsym(RTLD_NEXT, "sendmsg");
	}

	return real_sendmsg(fd, msg, flags);
#else
	return 0;
#endif
}

#ifdef INTERCEPT_IMSG
int
imsg_compose(struct imsgbuf *imsgbuf, uint32_t type, uint32_t id, pid_t pid, int fd, const void *data, uint16_t datalen) {

	int unint_location;

	printf("intercepting imsg_compose!!!\n");

	if ((unint_location = safe_msan_test_shadow(data, datalen)) != -1) {
		printf("intercepting imsg_compose sending a buffer contains unitialized memory! message len is %zu, and msan return is %d\n", datalen, unint_location);
		raise(SIGBUS);
	}

	check_pointers_with_vm_print(data, datalen);

	static int (*real_imsg_compose)(struct imsgbuf *, uint32_t, uint32_t, pid_t, int, const void *, size_t) = NULL;
	if (!real_imsg_compose) {
		real_imsg_compose = (int (*)(struct imsgbuf *, uint32_t, uint32_t, pid_t, int, const void *, size_t))dlsym(RTLD_NEXT, "imsg_compose");
	}

	return real_imsg_compose(imsgbuf, type, id, pid, fd, data, datalen);
}

int
imsg_composev(struct imsgbuf *imsgbuf, uint32_t type, uint32_t id, pid_t pid, int fd, const struct iovec *iov, int iovcnt) {

	printf("intercepting imsg_composev!!!\n");

	if (iov) {
		int iov_idx;
		for (iov_idx = 0; iov_idx < iovcnt; iov_idx++) {
			if (safe_msan_test_shadow(iov[iov_idx].iov_base, iov[iov_idx].iov_len) != -1) {
				printf("intercepting imsgcomposev sending a buffer contains unitialized memory! message len is %zu\n", iov[iov_idx].iov_len);
				raise(SIGBUS);
			}

			check_pointers_with_vm_print(iov[iov_idx].iov_base, iov[iov_idx].iov_len);
		}
	}

	static int (*real_imsg_composev)(struct imsgbuf *, uint32_t, uint32_t, pid_t, int, const struct iovec *, int) = NULL;
	if (!real_imsg_composev) {
		real_imsg_composev = (int (*)(struct imsgbuf *, uint32_t, uint32_t, pid_t, int, const struct iovec *, int))dlsym(RTLD_NEXT, "imsg_composev");
	}

	return real_imsg_composev(imsgbuf, type, id, pid, fd, iov, iovcnt);
}

#endif
