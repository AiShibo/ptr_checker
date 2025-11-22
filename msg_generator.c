#include "msg_generator.h"
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

/* Global variables for EOM counter */
static int expected_eom_count = 0;
static int current_eom_count = 0;

/**
 * Initialize the message interface structure
 * Sets up default 1:1 message type mapping
 */
int msg_interface_init(struct msg_interface *iface, int fuzzer_fd,
                       uint8_t num_compartments, uint8_t num_message_types)
{
    if (iface == NULL) {
        return MSG_GEN_ERROR;
    }

    /* Initialize basic fields */
    iface->fuzzer_fd = fuzzer_fd;
    iface->num_compartments = num_compartments;
    /* num_message_types: 0 means full range (256 types), 1-255 means that many types */
    iface->num_message_types = num_message_types;
    iface->messages_generated = 0;
    iface->eof_reached = 0;
    iface->eom_message_type = 0;  /* Default EOM type, should be set by user */

    /* Initialize message type mapping with 1:1 mapping */
    for (int i = 0; i < 256; i++) {
        iface->message_type_mapping[i] = i;
    }

    /* Initialize all endpoints to NULL */
    for (int i = 0; i < MAX_COMPARTMENTS; i++) {
        iface->endpoints[i] = NULL;
    }

    /* Initialize expected EOM count to number of compartments */
    eom_counter_init(num_compartments);

    return MSG_GEN_SUCCESS;
}

/**
 * Set a single message type mapping
 */
int msg_interface_set_message_type(struct msg_interface *iface,
                                    uint8_t index, int value)
{
    if (iface == NULL) {
        return MSG_GEN_ERROR;
    }

    iface->message_type_mapping[index] = value;

    /* Update num_message_types if needed */
    if (index >= iface->num_message_types) {
        iface->num_message_types = index + 1;
    }

    return MSG_GEN_SUCCESS;
}

/**
 * Batch set message type mappings with an offset
 */
int msg_interface_set_message_types_batch(struct msg_interface *iface,
                                           uint8_t starting_index,
                                           uint8_t count, int16_t offset)
{
    if (iface == NULL) {
        return MSG_GEN_ERROR;
    }

    /* Check for overflow */
    if ((uint16_t)starting_index + count > 256) {
        return MSG_GEN_ERROR;
    }

    for (uint8_t i = 0; i < count; i++) {
        uint8_t index = starting_index + i;
        int new_value = index + offset;

        iface->message_type_mapping[index] = new_value;
    }

    /* Update num_message_types if needed */
    uint8_t last_index = starting_index + count - 1;
    if (last_index >= iface->num_message_types) {
        iface->num_message_types = last_index + 1;
    }

    return MSG_GEN_SUCCESS;
}

/**
 * Set the endpoint for a specific compartment
 */
int msg_interface_set_endpoint(struct msg_interface *iface,
                                uint8_t compartment_id, void *endpoint)
{
    if (iface == NULL) {
        return MSG_GEN_ERROR;
    }

    iface->endpoints[compartment_id] = endpoint;

    return MSG_GEN_SUCCESS;
}

/**
 * Read payload data from fuzzer input
 */
uint16_t msg_read_payload(int fd, uint16_t size, char *buf)
{
    ssize_t bytes_read;
    size_t total_read = 0;

    while (total_read < size) {
        bytes_read = read(fd, buf + total_read, size - total_read);
        if (bytes_read <= 0) {
            break;
        }
        total_read += bytes_read;
    }

    return (uint16_t)total_read;
}

/**
 * Read metadata from fuzzer input
 */
int msg_read_metadata(struct msg_interface *iface, struct msg_data *msg)
{
    ssize_t bytes_read;

    /* Read compartment (1 byte) */
    bytes_read = read(iface->fuzzer_fd, &msg->compartment, sizeof(uint8_t));
    if (bytes_read != sizeof(uint8_t)) {
        return (bytes_read == 0) ? MSG_GEN_EOF : MSG_GEN_ERROR;
    }

    /* Read instance (1 byte) */
    bytes_read = read(iface->fuzzer_fd, &msg->instance, sizeof(uint8_t));
    if (bytes_read != sizeof(uint8_t)) {
        return MSG_GEN_ERROR;
    }

    /* Read type (1 byte) */
    bytes_read = read(iface->fuzzer_fd, &msg->type, sizeof(uint8_t));
    if (bytes_read != sizeof(uint8_t)) {
        return MSG_GEN_ERROR;
    }

    /* Read size (2 bytes) */
    bytes_read = read(iface->fuzzer_fd, &msg->size, sizeof(uint16_t));
    if (bytes_read != sizeof(uint16_t)) {
        return MSG_GEN_ERROR;
    }

    /* Read has_fd (1 byte) */
    bytes_read = read(iface->fuzzer_fd, &msg->has_fd, sizeof(uint8_t));
    if (bytes_read != sizeof(uint8_t)) {
        return MSG_GEN_ERROR;
    }

    /* Read fd_perm (1 byte) */
    bytes_read = read(iface->fuzzer_fd, &msg->fd_perm, sizeof(uint8_t));
    if (bytes_read != sizeof(uint8_t)) {
        return MSG_GEN_ERROR;
    }

    /* Read fd_data_len (2 bytes) */
    bytes_read = read(iface->fuzzer_fd, &msg->fd_data_len, sizeof(uint16_t));
    if (bytes_read != sizeof(uint16_t)) {
        return MSG_GEN_ERROR;
    }

    /* Read auxiliary data (64 bytes) - must read all 64 bytes */
    size_t aux_total_read = 0;
    while (aux_total_read < 64) {
        bytes_read = read(iface->fuzzer_fd, msg->aux_data + aux_total_read, 64 - aux_total_read);
        if (bytes_read <= 0) {
            /* Failed to read all 64 bytes - this is an error */
            return MSG_GEN_ERROR;
        }
        aux_total_read += bytes_read;
    }

    /* Normalize values using modulo for equal probability */

    /* Compartment: use modulo with num_compartments */
    if (iface->num_compartments > 0) {
        msg->compartment = msg->compartment % iface->num_compartments;
    }

    /* Message size: modulo with MAX_MESSAGE_LENGTH */
    msg->size = msg->size % MAX_MESSAGE_LENGTH;

    /* has_fd: modulo 2 for equal probability of 0 or 1 */
    msg->has_fd = msg->has_fd % 2;

    /* fd_perm: modulo to get valid permission values */
    /* Values should be 1 (read), 2 (write), or 3 (both) */
    msg->fd_perm = (msg->fd_perm % 3) + 1;

    /* fd_data_len: modulo with MAX_MESSAGE_LENGTH */
    msg->fd_data_len = msg->fd_data_len % MAX_MESSAGE_LENGTH;

    /* type: modulo with maximum number of messages */
    /* Normalize to valid message type index (0 to num_message_types-1) */
    if (iface->num_message_types > 0) {
        msg->type = msg->type % iface->num_message_types;
    }

    return MSG_GEN_SUCCESS;
}

/**
 * Generate a single message from fuzzer input
 */
int msg_generate(struct msg_interface *iface, struct msg_data *msg)
{
    int ret;

    if (iface == NULL || msg == NULL) {
        return MSG_GEN_ERROR;
    }

    /* Check if EOF was already reached */
    if (iface->eof_reached) {
        return MSG_GEN_EOF;
    }

    /* Zero out the message structure */
    memset(msg, 0, sizeof(struct msg_data));
    msg->fd = -1;  /* Initialize fd to invalid */

    /* Read metadata */
    ret = msg_read_metadata(iface, msg);
    if (ret != MSG_GEN_SUCCESS) {
        if (ret == MSG_GEN_EOF) {
            iface->eof_reached = 1;
        }
        return ret;
    }

    /* Apply message type mapping */
    msg->type = iface->message_type_mapping[msg->type];

    /* Get the endpoint for this compartment */
    msg->endpoint = iface->endpoints[msg->compartment];

    /* Read message payload */
    if (msg->size > 0) {
        msg->actual_payload_size = msg_read_payload(iface->fuzzer_fd,
                                                     msg->size, msg->payload);

        /* If we couldn't read the full payload, mark EOF for next call */
        if (msg->actual_payload_size < msg->size) {
            iface->eof_reached = 1;
        }
    } else {
        msg->actual_payload_size = 0;
    }

    /* Handle FD if present */
    if (msg->has_fd) {
        /* Read FD data if fd_data_len > 0 */
        if (msg->fd_data_len > 0) {
            msg->actual_fd_size = msg_read_payload(iface->fuzzer_fd,
                                                    msg->fd_data_len,
                                                    msg->fd_payload);

            /* If we couldn't read the full FD payload, mark no FD and EOF for next call */
            if (msg->actual_fd_size < msg->fd_data_len) {
                msg->has_fd = 0;
                msg->fd = -1;
                iface->eof_reached = 1;
                goto done;
            }
        } else {
            msg->actual_fd_size = 0;
        }

        /* Create a UNIX socket pair for the FD */
        int sockfd[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) == -1) {
            msg->has_fd = 0;
            msg->fd = -1;
            return MSG_GEN_ERROR;
        }

        /* Write the FD data to the socket if there is any */
        if (msg->actual_fd_size > 0) {
            ssize_t written = 0;
            ssize_t total_written = 0;
            while (total_written < msg->actual_fd_size) {
                written = write(sockfd[1], msg->fd_payload + total_written,
                                msg->actual_fd_size - total_written);
                if (written <= 0) {
                    close(sockfd[0]);
                    close(sockfd[1]);
                    msg->has_fd = 0;
                    msg->fd = -1;
                    return MSG_GEN_ERROR;
                }
                total_written += written;
            }
        }

        /* Close the write end and store the read end */
        close(sockfd[1]);
        msg->fd = sockfd[0];

        /* Apply permissions based on fd_perm */
        if (msg->fd_perm == FD_PERM_READ) {
            /* Read-only: shutdown write side */
            if (shutdown(msg->fd, SHUT_WR) == -1) {
                close(msg->fd);
                msg->has_fd = 0;
                msg->fd = -1;
                return MSG_GEN_ERROR;
            }
        } else if (msg->fd_perm == FD_PERM_WRITE) {
            /* Write-only: shutdown read side */
            if (shutdown(msg->fd, SHUT_RD) == -1) {
                close(msg->fd);
                msg->has_fd = 0;
                msg->fd = -1;
                return MSG_GEN_ERROR;
            }
        }
        /* FD_PERM_BOTH: leave both directions open, no shutdown needed */
    } else {
        msg->actual_fd_size = 0;
        msg->fd = -1;
    }

done:
    /* Increment message counter */
    iface->messages_generated++;

    return MSG_GEN_SUCCESS;
}

/**
 * Set the EOM (End of Message) message type
 */
void msg_interface_set_eom_type(struct msg_interface *iface, int eom_type)
{
    if (iface == NULL) {
        return;
    }

    iface->eom_message_type = eom_type;
}

/**
 * Generate an EOM message for a specific compartment
 */
int msg_generate_eom(struct msg_interface *iface, uint8_t compartment_id,
                      struct msg_data *msg)
{
    if (iface == NULL || msg == NULL) {
        return MSG_GEN_ERROR;
    }

    if (compartment_id >= iface->num_compartments) {
        return MSG_GEN_ERROR;
    }

    /* Zero out the message structure */
    memset(msg, 0, sizeof(struct msg_data));

    /* Set EOM message fields */
    msg->compartment = compartment_id;
    msg->instance = 0;
    msg->type = iface->eom_message_type;
    msg->size = 0;
    msg->has_fd = 0;
    msg->fd_perm = 0;
    msg->fd_data_len = 0;
    msg->actual_payload_size = 0;
    msg->actual_fd_size = 0;
    msg->fd = -1;

    /* Get the endpoint for this compartment */
    msg->endpoint = iface->endpoints[compartment_id];

    return MSG_GEN_SUCCESS;
}

/**
 * Initialize the EOM counter
 */
void eom_counter_init(int expected_eom)
{
    expected_eom_count = expected_eom;
    current_eom_count = 0;
}

/**
 * Increment the EOM counter
 */
void eom_counter_inc(void)
{
    current_eom_count++;
    printf("%d number of eoms received!, %d expected\n",
           current_eom_count, expected_eom_count);

    if (current_eom_count >= expected_eom_count && expected_eom_count > 0) {
        exit(0);
    }
}
