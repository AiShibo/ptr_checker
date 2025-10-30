#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include "ptr_check_lib.h"

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

ssize_t write(int fd, const void *buf, size_t nbytes) {
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

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
	if (msg && msg->msg_iov) {
		int iov_idx;
		for (iov_idx = 0; iov_idx < msg->msg_iovlen; iov_idx++) {
			printf("intercepting sendmsg!!!\n");
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

int
imsg_compose(struct imsgbuf *imsgbuf, uint32_t type, uint32_t id, pid_t pid, int fd, const void *data, size_t datalen) {
	(void)imsgbuf;
	(void)type;
	(void)id;
	(void)pid;
	(void)fd;

	printf("intercepting imsg_compose!!!\n");
	check_pointers_with_vm_print(data, datalen);
	return 1;
}
