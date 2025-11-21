/*
 * fd_sender_test.c - Test harness for FD sending using msg_generator library
 *
 * This test demonstrates the msg_generator library's ability to:
 * 1. Generate messages with file descriptors
 * 2. Send data through those file descriptors
 * 3. Verify the receiving end can read the data correctly
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>

#include "../msg_generator.h"

#define TEST_MESSAGE_TYPE 42
#define TEST_COMPARTMENT 0

/*
 * Send a file descriptor over a UNIX socket
 * Returns 0 on success, -1 on error
 */
int send_fd(int sock, int fd_to_send)
{
    struct msghdr msg = {0};
    struct iovec iov[1];
    char buf[1] = {'X'};  /* Dummy data */
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;

    /* Setup the data payload (at least 1 byte required) */
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    /* Setup the control message to send the FD */
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    if (sendmsg(sock, &msg, 0) < 0) {
        perror("sendmsg");
        return -1;
    }

    return 0;
}

/*
 * Create a pipe containing fuzzer input for testing
 * Returns the read end of the pipe, -1 on error
 */
int create_test_input(void)
{
    int pipefd[2];

    if (pipe(pipefd) < 0) {
        perror("pipe");
        return -1;
    }

    /* Write test fuzzer input:
     * Metadata (9 bytes):
     *   - compartment: 0
     *   - instance: 0
     *   - type: 42
     *   - size: 100 (message payload)
     *   - has_fd: 1
     *   - fd_perm: 2 -> (2 % 3) + 1 = 3 (read+write/FD_PERM_BOTH)
     *   - fd_data_len: 50 (FD data size)
     */
    unsigned char metadata[9] = {
        0x00,           /* compartment */
        0x00,           /* instance */
        0x2A,           /* type = 42 */
        0x64, 0x00,     /* size = 100 (little-endian) */
        11,           /* has_fd = 1 */
        0x00,           /* fd_perm = 2 -> becomes 3 (FD_PERM_BOTH) */
        0x32, 0x00      /* fd_data_len = 50 (little-endian) */
    };

    write(pipefd[1], metadata, sizeof(metadata));

    /* Write message payload (100 bytes) */
    char msg_payload[100];
    memset(msg_payload, 'M', sizeof(msg_payload));
    snprintf(msg_payload, sizeof(msg_payload), "MESSAGE_PAYLOAD_DATA");
    write(pipefd[1], msg_payload, sizeof(msg_payload));

    /* Write FD data (50 bytes) - this will be sent through the created FD */
    char fd_data[50];
    memset(fd_data, 'F', sizeof(fd_data));
    snprintf(fd_data, sizeof(fd_data), "TEST_DATA_via_FD");
    write(pipefd[1], fd_data, sizeof(fd_data));

    close(pipefd[1]);  /* Close write end */
    return pipefd[0];  /* Return read end */
}

/*
 * Run the sender test (parent process)
 */
int run_sender_test(int control_sock, int fuzzer_input_fd)
{
    struct msg_interface iface;
    struct msg_data msg;
    int result;

    printf("[SENDER] Initializing message interface...\n");

    /* Initialize with 1 compartment, 256 message types */
    if (msg_interface_init(&iface, fuzzer_input_fd, 1, 0) != MSG_GEN_SUCCESS) {
        fprintf(stderr, "[SENDER] Failed to initialize interface\n");
        return -1;
    }

    /* Set endpoint (we don't actually use this in this test) */
    msg_interface_set_endpoint(&iface, 0, NULL);

    printf("[SENDER] Generating message from fuzzer input...\n");

    /* Generate a message (should include FD) */
    result = msg_generate(&iface, &msg);

    if (result == MSG_GEN_EOF) {
        fprintf(stderr, "[SENDER] Unexpected EOF from fuzzer input\n");
        return -1;
    } else if (result == MSG_GEN_ERROR) {
        fprintf(stderr, "[SENDER] Error generating message\n");
        return -1;
    }

    printf("[SENDER] Message generated successfully:\n");
    printf("[SENDER]   Compartment: %u\n", msg.compartment);
    printf("[SENDER]   Type: %u\n", msg.type);
    printf("[SENDER]   Payload size: %u\n", msg.actual_payload_size);
    printf("[SENDER]   Has FD: %u\n", msg.has_fd);
    printf("[SENDER]   FD permissions: %u (1=read, 2=write, 3=both)\n", msg.fd_perm);
    printf("[SENDER]   FD data size: %u\n", msg.actual_fd_size);
    printf("[SENDER]   FD number: %d\n", msg.fd);

    if (!msg.has_fd || msg.fd < 0) {
        fprintf(stderr, "[SENDER] Expected message to have FD, but it doesn't\n");
        return -1;
    }

    /* Print first few bytes of FD data */
    printf("[SENDER] FD data (first 32 bytes): ");
    for (int i = 0; i < 32 && i < msg.actual_fd_size; i++) {
        printf("%02x ", (unsigned char)msg.fd_payload[i]);
    }
    printf("\n");

    /* Send the FD to the receiver process */
    printf("[SENDER] Sending FD %d to receiver...\n", msg.fd);
    if (send_fd(control_sock, msg.fd) < 0) {
        fprintf(stderr, "[SENDER] Failed to send FD\n");
        close(msg.fd);
        return -1;
    }

    printf("[SENDER] FD sent successfully\n");

    /* Close our copy of the FD */
    close(msg.fd);

    return 0;
}

int main(void)
{
    int control_sockets[2];
    int fuzzer_input_fd;
    pid_t child_pid;
    int status;
    int result = 0;

    printf("=== FD Sender/Receiver Test ===\n\n");

    /* Create a UNIX socket pair for control (sending FDs) */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, control_sockets) < 0) {
        perror("socketpair");
        return 1;
    }

    /* Create test fuzzer input */
    fuzzer_input_fd = create_test_input();
    if (fuzzer_input_fd < 0) {
        fprintf(stderr, "Failed to create test input\n");
        return 1;
    }

    /* Fork to create sender and receiver processes */
    child_pid = fork();

    if (child_pid < 0) {
        perror("fork");
        return 1;
    }

    if (child_pid == 0) {
        /* Child process: receiver */
        close(control_sockets[0]);  /* Close parent's end */
        close(fuzzer_input_fd);     /* Don't need this in receiver */

        /* Execute the receiver program */
        char fd_str[16];
        snprintf(fd_str, sizeof(fd_str), "%d", control_sockets[1]);

        execl("./fd_receiver", "fd_receiver", fd_str, NULL);

        /* If execl returns, it failed */
        perror("execl");
        exit(1);
    } else {
        /* Parent process: sender */
        close(control_sockets[1]);  /* Close child's end */

        /* Run the sender test */
        if (run_sender_test(control_sockets[0], fuzzer_input_fd) < 0) {
            fprintf(stderr, "[SENDER] Test failed\n");
            result = 1;
        }

        close(control_sockets[0]);
        close(fuzzer_input_fd);

        /* Wait for child to finish */
        printf("\n[SENDER] Waiting for receiver to finish...\n");
        if (waitpid(child_pid, &status, 0) < 0) {
            perror("waitpid");
            return 1;
        }

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            printf("\n[SENDER] Receiver exited with code %d\n", exit_code);
            if (exit_code != 0) {
                result = 1;
            }
        } else {
            fprintf(stderr, "\n[SENDER] Receiver terminated abnormally\n");
            result = 1;
        }
    }

    printf("\n=== Test %s ===\n", result == 0 ? "PASSED" : "FAILED");
    return result;
}
