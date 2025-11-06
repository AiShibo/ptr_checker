#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include "buffer_check_lib.h"
#include <stdatomic.h>

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

#ifdef INTERCEPT_SENDMSG
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
	if (msg && msg->msg_iov) {
		int iov_idx;
		for (iov_idx = 0; iov_idx < msg->msg_iovlen; iov_idx++) {
			check_buffer(msg->msg_iov[iov_idx].iov_base,
			             msg->msg_iov[iov_idx].iov_len);
		}
	}

	static ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = NULL;
	if (!real_sendmsg) {
		real_sendmsg = (ssize_t (*)(int, const struct msghdr *, int))dlsym(RTLD_NEXT, "sendmsg");
	}

	return real_sendmsg(fd, msg, flags);
}
#endif

#ifdef INTERCEPT_IMSG_COMPOSE
int
imsg_compose(struct imsgbuf *imsgbuf, uint32_t type, uint32_t id, pid_t pid, int fd, const void *data, uint16_t datalen) {
	printf("intercepting imsg_compose!!!\n");

	check_buffer(data, datalen);

	static int (*real_imsg_compose)(struct imsgbuf *, uint32_t, uint32_t, pid_t, int, const void *, size_t) = NULL;
	if (!real_imsg_compose) {
		real_imsg_compose = (int (*)(struct imsgbuf *, uint32_t, uint32_t, pid_t, int, const void *, size_t))dlsym(RTLD_NEXT, "imsg_compose");
	}

	return real_imsg_compose(imsgbuf, type, id, pid, fd, data, datalen);
}
#endif

#ifdef INTERCEPT_IMSG_COMPOSEV
int
imsg_composev(struct imsgbuf *imsgbuf, uint32_t type, uint32_t id, pid_t pid, int fd, const struct iovec *iov, int iovcnt) {
	printf("intercepting imsg_composev!!!\n");

	if (iov) {
		int iov_idx;
		for (iov_idx = 0; iov_idx < iovcnt; iov_idx++) {
			check_buffer(iov[iov_idx].iov_base, iov[iov_idx].iov_len);
		}
	}

	static int (*real_imsg_composev)(struct imsgbuf *, uint32_t, uint32_t, pid_t, int, const struct iovec *, int) = NULL;
	if (!real_imsg_composev) {
		real_imsg_composev = (int (*)(struct imsgbuf *, uint32_t, uint32_t, pid_t, int, const struct iovec *, int))dlsym(RTLD_NEXT, "imsg_composev");
	}

	return real_imsg_composev(imsgbuf, type, id, pid, fd, iov, iovcnt);
}
#endif
