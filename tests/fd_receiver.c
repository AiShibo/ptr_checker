/*
 * fd_receiver.c - Test program that receives data via file descriptor
 *
 * This program simulates a receiving compartment that gets a file descriptor
 * and reads data from it. It validates the data received matches expectations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdint.h>

#define BUFFER_SIZE 8192

/*
 * Receive a file descriptor over a UNIX socket
 * Returns the received FD on success, -1 on error
 */
int recv_fd(int sock)
{
    struct msghdr msg = {0};
    struct iovec iov[1];
    char buf[1];
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;
    int received_fd = -1;

    /* Setup to receive at least one byte of data */
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    if (recvmsg(sock, &msg, 0) < 0) {
        perror("recvmsg");
        return -1;
    }

    /* Extract the file descriptor from the control message */
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));
            break;
        }
    }

    return received_fd;
}

/*
 * Read data from a file descriptor and verify its contents
 * Returns 0 on success, -1 on error
 */
int read_and_verify_fd(int fd, const char *expected_prefix)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    size_t total_read = 0;

    printf("[RECEIVER] Reading data from FD %d...\n", fd);

    /* Try multiple reads to get all available data */
    int read_attempts = 0;
    while (total_read < BUFFER_SIZE && read_attempts < 10) {
        bytes_read = read(fd, buffer + total_read, BUFFER_SIZE - total_read);
        read_attempts++;

        printf("[RECEIVER] Read attempt %d: %zd bytes\n", read_attempts, bytes_read);

        if (bytes_read < 0) {
            perror("[RECEIVER] read error");
            return -1;
        }
        if (bytes_read == 0) {
            /* EOF reached */
            printf("[RECEIVER] EOF reached after %zu bytes\n", total_read);
            break;
        }
        total_read += bytes_read;
    }

    printf("[RECEIVER] Read %zu bytes from FD\n", total_read);

    if (total_read > 0) {
        /* Print first 64 bytes or total_read, whichever is smaller */
        size_t print_len = total_read < 64 ? total_read : 64;
        printf("[RECEIVER] First %zu bytes (hex): ", print_len);
        for (size_t i = 0; i < print_len; i++) {
            printf("%02x ", (unsigned char)buffer[i]);
        }
        printf("\n");

        /* If expected_prefix provided, verify it */
        if (expected_prefix != NULL) {
            size_t prefix_len = strlen(expected_prefix);
            if (total_read >= prefix_len &&
                memcmp(buffer, expected_prefix, prefix_len) == 0) {
                printf("[RECEIVER] ✓ Data verification PASSED\n");
                return 0;
            } else {
                printf("[RECEIVER] ✗ Data verification FAILED\n");
                printf("[RECEIVER]   Expected prefix: '%s'\n", expected_prefix);
                printf("[RECEIVER]   Received data does not match\n");
                return -1;
            }
        }
    } else {
        printf("[RECEIVER] No data received from FD\n");
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int control_sock;
    int received_fd;
    int result = 0;

    printf("=== FD Receiver Test Program ===\n");

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <control_socket_fd>\n", argv[0]);
        fprintf(stderr, "  control_socket_fd: FD number for receiving file descriptors\n");
        return 1;
    }

    control_sock = atoi(argv[1]);
    printf("[RECEIVER] Control socket FD: %d\n", control_sock);

    /* Receive the file descriptor */
    printf("[RECEIVER] Waiting to receive FD...\n");
    received_fd = recv_fd(control_sock);

    if (received_fd < 0) {
        fprintf(stderr, "[RECEIVER] Failed to receive FD\n");
        return 1;
    }

    printf("[RECEIVER] Received FD: %d\n", received_fd);

    /* Read and verify data from the FD */
    if (read_and_verify_fd(received_fd, "TEST_DATA_") < 0) {
        result = 1;
    }

    /* Clean up */
    close(received_fd);
    close(control_sock);

    printf("[RECEIVER] Test %s\n", result == 0 ? "PASSED" : "FAILED");
    return result;
}
