#ifndef MSG_GENERATOR_H
#define MSG_GENERATOR_H

#include <stdint.h>
#include <stddef.h>

/* Design parameters */
#define MAX_MESSAGE_LENGTH 8192
#define MAX_NUM_MESSAGES 1024
#define MAX_COMPARTMENTS 256

/* FD permissions */
#define FD_PERM_READ  0x01
#define FD_PERM_WRITE 0x02
#define FD_PERM_BOTH  (FD_PERM_READ | FD_PERM_WRITE)

/* Return values */
#define MSG_GEN_SUCCESS 0
#define MSG_GEN_EOF 1
#define MSG_GEN_ERROR -1

/**
 * Structure describing a single inter-compartment message
 * This contains all metadata and payload for one message
 */
struct msg_data {
    /* Message metadata */
    uint8_t compartment;      /* Target compartment ID */
    uint8_t instance;         /* Instance number (reserved, not used) */
    int type;                 /* Message type */
    uint16_t size;            /* Message payload size */

    /* FD-related metadata */
    uint8_t has_fd;           /* Does this message include an FD? (0 or 1) */
    uint8_t fd_perm;          /* FD permissions (read/write/both) */
    uint16_t fd_data_len;     /* Length of data to send via FD */

    /* Payload data */
    char payload[MAX_MESSAGE_LENGTH];  /* Message payload buffer */
    uint16_t actual_payload_size;      /* Actual bytes read for payload */

    /* FD payload */
    char fd_payload[MAX_MESSAGE_LENGTH]; /* FD data buffer (if has_fd is set) */
    uint16_t actual_fd_size;             /* Actual bytes read for FD data */
    int fd;                              /* Created file descriptor (if has_fd is set) */

    /* Communication endpoint */
    void *endpoint;           /* Pointer to communication endpoint (e.g., imsgbuf*) */
};

/**
 * Structure describing the interface metadata
 * This contains information about the compartment communication interface
 */
struct msg_interface {
    /* Fuzzer input source */
    int fuzzer_fd;            /* File descriptor for fuzzer input (typically stdin) */

    /* Compartment information */
    uint8_t num_compartments; /* Number of compartments */

    /* Message type mapping - maps fuzzer message type to actual message type */
    /* Initialized with 1:1 mapping by default (index 0 -> 0, index 1 -> 1, etc.) */
    int message_type_mapping[256];     /* Array mapping fuzzer type index to actual type value */
    uint8_t num_message_types;         /* Number of valid message types */

    /* Communication endpoints */
    void *endpoints[MAX_COMPARTMENTS]; /* Array of endpoint pointers (indexed by compartment) */

    /* EOM (End of Message) support */
    int eom_message_type;      /* Message type to use for EOM messages */

    /* State */
    uint32_t messages_generated; /* Counter for messages generated */
    int eof_reached;          /* Flag indicating if EOF has been reached */
};

/**
 * Initialize the message interface structure
 * Sets up default 1:1 message type mapping
 *
 * @param iface Pointer to msg_interface structure to initialize
 * @param fuzzer_fd File descriptor for fuzzer input
 * @param num_compartments Number of compartments in the system
 * @param num_message_types Number of valid message types (0-255, where 0 means use all 256 types)
 * @return MSG_GEN_SUCCESS on success, MSG_GEN_ERROR on failure
 */
int msg_interface_init(struct msg_interface *iface, int fuzzer_fd,
                       uint8_t num_compartments, uint8_t num_message_types);

/**
 * Set a single message type mapping
 * Maps fuzzer message type index to actual message type value
 *
 * @param iface Pointer to msg_interface structure
 * @param index Message type index from fuzzer (0-based)
 * @param value Actual message type value to use
 * @return MSG_GEN_SUCCESS on success, MSG_GEN_ERROR on failure
 */
int msg_interface_set_message_type(struct msg_interface *iface,
                                    uint8_t index, int value);

/**
 * Batch set message type mappings with an offset
 * For example: starting_index=4, count=3, offset=96 will set:
 *   index 4 -> value 100 (4 + 96)
 *   index 5 -> value 101 (5 + 96)
 *   index 6 -> value 102 (6 + 96)
 *
 * @param iface Pointer to msg_interface structure
 * @param starting_index First message type index to set
 * @param count Number of consecutive message types to set
 * @param offset Value to add to each index to get the actual message type
 * @return MSG_GEN_SUCCESS on success, MSG_GEN_ERROR on failure
 */
int msg_interface_set_message_types_batch(struct msg_interface *iface,
                                           uint8_t starting_index,
                                           uint8_t count, int16_t offset);

/**
 * Set the endpoint for a specific compartment
 *
 * @param iface Pointer to msg_interface structure
 * @param compartment_id Compartment ID
 * @param endpoint Pointer to the communication endpoint (e.g., imsgbuf*)
 * @return MSG_GEN_SUCCESS on success, MSG_GEN_ERROR on failure
 */
int msg_interface_set_endpoint(struct msg_interface *iface,
                                uint8_t compartment_id, void *endpoint);

/**
 * Set the EOM (End of Message) message type
 *
 * @param iface Pointer to msg_interface structure
 * @param eom_type Message type value to use for EOM messages
 */
void msg_interface_set_eom_type(struct msg_interface *iface, int eom_type);

/**
 * Generate an EOM message for a specific compartment
 * Creates a message with no payload and no FD
 *
 * @param iface Pointer to msg_interface structure
 * @param compartment_id Target compartment ID
 * @param msg Pointer to msg_data structure to populate
 * @return MSG_GEN_SUCCESS on success, MSG_GEN_ERROR on failure
 */
int msg_generate_eom(struct msg_interface *iface, uint8_t compartment_id,
                      struct msg_data *msg);

/**
 * Generate a single message from fuzzer input
 * This reads metadata and payload from the fuzzer input and populates the msg_data structure
 *
 * @param iface Pointer to msg_interface structure
 * @param msg Pointer to msg_data structure to populate
 * @return MSG_GEN_SUCCESS on success, MSG_GEN_EOF if no more data available,
 *         MSG_GEN_ERROR on error
 */
int msg_generate(struct msg_interface *iface, struct msg_data *msg);

/**
 * Read metadata from fuzzer input
 * Internal function used by msg_generate
 *
 * @param iface Pointer to msg_interface structure
 * @param msg Pointer to msg_data structure to populate
 * @return MSG_GEN_SUCCESS on success, MSG_GEN_EOF if EOF reached,
 *         MSG_GEN_ERROR on error
 */
int msg_read_metadata(struct msg_interface *iface, struct msg_data *msg);

/**
 * Read payload data from fuzzer input
 * Internal function used by msg_generate
 *
 * @param fd File descriptor to read from
 * @param size Number of bytes to read
 * @param buf Buffer to read into
 * @return Number of bytes actually read (may be less than size if EOF reached)
 */
uint16_t msg_read_payload(int fd, uint16_t size, char *buf);

/*
 * EOM (End of Message) Counter Support
 * Used by receiving compartments to track when all EOMs have been received
 *
 * Note: The EOM counter is automatically initialized when calling msg_interface_init(),
 * which sets the expected EOM count to the number of compartments.
 */

/**
 * Initialize the EOM counter
 * Sets the expected number of EOM messages before program termination
 *
 * @param expected_eom Expected number of EOM messages to receive
 */
void eom_counter_init(int expected_eom);

/**
 * Increment the EOM counter
 * If the count reaches the expected number, the program exits with status 0
 */
void eom_counter_inc(void);

#endif /* MSG_GENERATOR_H */
