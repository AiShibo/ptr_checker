# Message Generator Library Guide

## Overview

The Message Generator Library is a fuzzer-driven library for generating inter-compartment messages in privilege-separated applications. It reads fuzzer input from a file descriptor (typically stdin) and generates structured messages with metadata, payloads, and optional file descriptors.

## Core Concepts

### Design Philosophy

The library separates concerns into two main structures:

1. **Interface Metadata (`msg_interface`)** - Describes the communication interface itself
   - How many compartments exist
   - Which message types are valid
   - Where messages should be sent (endpoints)
   - The source of fuzzer input

2. **Message Data (`msg_data`)** - Describes a single message
   - Target compartment
   - Message type and size
   - Message payload
   - Optional file descriptor with data and permissions

### Key Design Decisions

- **No Dynamic Allocation**: Uses fixed-size arrays for source-level compatibility and safety
- **Modulo Normalization**: Fuzzer-generated values are normalized using modulo for equal probability distribution
- **1:1 Default Mapping**: Message types default to identity mapping (0→0, 1→1, etc.) with optional customization
- **Graceful EOF Handling**: When fuzzer input runs out, the library returns EOF on subsequent calls
- **UNIX Socketpair for FDs**: Creates real file descriptors with proper read/write permissions

## Data Structures

### `struct msg_interface`

Describes the communication interface:

```c
struct msg_interface {
    int fuzzer_fd;                          // Source of fuzzer input (e.g., STDIN_FILENO)
    uint8_t num_compartments;               // Number of compartments
    uint8_t message_type_mapping[256];      // Maps fuzzer type → actual type
    uint8_t num_message_types;              // Number of valid message types
    void *endpoints[MAX_COMPARTMENTS];      // Communication endpoints (e.g., imsgbuf*)
    uint32_t messages_generated;            // Counter
    int eof_reached;                        // EOF flag
};
```

### `struct msg_data`

Describes a single message:

```c
struct msg_data {
    // Metadata
    uint8_t compartment;                    // Target compartment (normalized)
    uint8_t instance;                       // Reserved, not used
    uint8_t type;                           // Message type (after mapping)
    uint16_t size;                          // Payload size (normalized)

    // FD metadata
    uint8_t has_fd;                         // 0 or 1 (modulo 2)
    uint8_t fd_perm;                        // 1=read, 2=write, 3=both (modulo 3 + 1)
    uint16_t fd_data_len;                   // FD data size (normalized)

    // Auxiliary data
    char aux_data[64];                      // 64 bytes for non-payload data (e.g., pid, IDs)

    // Payloads
    char payload[MAX_MESSAGE_LENGTH];       // Message payload
    uint16_t actual_payload_size;           // Actual bytes read
    char fd_payload[MAX_MESSAGE_LENGTH];    // FD data
    uint16_t actual_fd_size;                // Actual FD bytes read
    int fd;                                 // Created file descriptor (-1 if none)

    // Endpoint
    void *endpoint;                         // Target endpoint
};
```

## EOM (End of Message) Support

The library includes integrated support for End-of-Message (EOM) handling:

### Sending Side (Message Generator)
- Configure EOM message type with `msg_interface_set_eom_type()`
- Generate EOM messages for each compartment with `msg_generate_eom()`

### Receiving Side (EOM Counter)
- Expected EOM count is **automatically initialized** to `num_compartments` when calling `msg_interface_init()`
- Can be manually adjusted with `eom_counter_init()` if needed
- Call `eom_counter_inc()` when an EOM message is received
- Program automatically exits when all expected EOMs are received

## API Reference

### Initialization

```c
int msg_interface_init(struct msg_interface *iface, int fuzzer_fd,
                       uint8_t num_compartments, uint8_t num_message_types);
```

Initializes the interface with:
- Default 1:1 message type mapping
- All endpoints set to NULL
- Fuzzer input source
- **Number of valid message types** (0 = use all 256 types, or specify 1-255 for a specific count)
- **Expected EOM count automatically set to `num_compartments`**

**Returns**: `MSG_GEN_SUCCESS` or `MSG_GEN_ERROR`

### Configuration

#### Set Individual Message Type

```c
int msg_interface_set_message_type(struct msg_interface *iface,
                                    uint8_t index, uint8_t value);
```

Maps fuzzer message type `index` to actual message type `value`.

**Example**: `msg_interface_set_message_type(&iface, 0, 100)` → fuzzer type 0 becomes actual type 100

#### Batch Set Message Types

```c
int msg_interface_set_message_types_batch(struct msg_interface *iface,
                                           uint8_t starting_index,
                                           uint8_t count, int16_t offset);
```

Sets multiple consecutive message types with an offset.

**Example**: `msg_interface_set_message_types_batch(&iface, 4, 3, 96)` sets:
- Index 4 → 100 (4 + 96)
- Index 5 → 101 (5 + 96)
- Index 6 → 102 (6 + 96)

**Use case**: Handle message enums like `{0, 1, 2, 3, 100, 101, 102, ...}`

#### Set Endpoint

```c
int msg_interface_set_endpoint(struct msg_interface *iface,
                                uint8_t compartment_id, void *endpoint);
```

Associates a compartment with its communication endpoint (e.g., `imsgbuf*`).

#### Set EOM Type

```c
void msg_interface_set_eom_type(struct msg_interface *iface, uint8_t eom_type);
```

Sets the message type value to use for End-of-Message (EOM) messages.

**Example**: `msg_interface_set_eom_type(&iface, IMSG_EOM);`

### Message Generation

```c
int msg_generate(struct msg_interface *iface, struct msg_data *msg);
```

Generates a single message from fuzzer input.

**Returns**:
- `MSG_GEN_SUCCESS` - Message generated successfully
- `MSG_GEN_EOF` - No more fuzzer input available
- `MSG_GEN_ERROR` - Error occurred

**What it does**:
1. Reads 9 bytes of basic metadata from fuzzer input
2. Reads 64 bytes of auxiliary data (fails if incomplete)
3. Normalizes values using modulo
4. Applies message type mapping
5. Reads message payload
6. If `has_fd=1`, reads FD data and creates a UNIX socketpair with proper permissions
7. Populates `msg->endpoint` for the target compartment

#### Generate EOM Message

```c
int msg_generate_eom(struct msg_interface *iface, uint8_t compartment_id,
                      struct msg_data *msg);
```

Generates an End-of-Message (EOM) message for a specific compartment.

**Returns**: `MSG_GEN_SUCCESS` or `MSG_GEN_ERROR`

**What it does**:
- Creates a message with no payload and no FD
- Sets the message type to the configured EOM type
- Populates the endpoint for the target compartment

**Example usage**:
```c
struct msg_data eom_msg;

/* Send EOM to all compartments */
for (uint8_t i = 0; i < iface.num_compartments; i++) {
    if (msg_generate_eom(&iface, i, &eom_msg) == MSG_GEN_SUCCESS) {
        struct imsgbuf *target = (struct imsgbuf *)eom_msg.endpoint;
        imsg_compose(target, eom_msg.type, 0, 0, -1, NULL, 0);
        imsg_flush(target);
    }
}
```

### EOM Counter Functions

These functions are used by **receiving compartments** to track EOMs:

#### Initialize EOM Counter

```c
void eom_counter_init(int expected_eom);
```

Sets the expected number of EOM messages. When this count is reached, the program exits.

**Note**: The expected EOM count is automatically initialized to `num_compartments` when you call `msg_interface_init()`. You only need to call this function if you want to override the default value.

#### Increment EOM Counter

```c
void eom_counter_inc(void);
```

Call this when an EOM message is received. Prints debug info and exits when expected count is reached.

#### Initialize from Interface

```c
void eom_counter_init_from_interface(struct msg_interface *iface);
```

Helper that sets expected EOMs to `num_compartments`. Useful when each compartment sends one EOM.

**Example usage in receiving compartment**:
```c
/* EOM counter is already initialized automatically by msg_interface_init() */

/* In message handler */
switch (imsg.hdr.type) {
    case IMSG_EOM:
        eom_counter_inc();  /* Increments and exits when all EOMs received */
        break;
    /* ... other message types ... */
}
```

## Converting Existing Code

### Original Code Pattern

From `claude.txt`, the original code looks like:

```c
struct imsgbuf server_ibuf;
int server_fd = ps->ps_pipes[PROC_SERVER][0].pp_pipes[PROC_PARENT][0];
imsg_init(&server_ibuf, server_fd);

struct imsgbuf logger_ibuf;
int logger_fd = ps->ps_pipes[PROC_LOGGER][0].pp_pipes[PROC_PARENT][0];
imsg_init(&logger_ibuf, logger_fd);

while(1) {
    uint8_t compartment;
    uint8_t instance;
    uint8_t type;
    uint16_t size;
    char payload[65535];
    uint16_t payload_size;

    /* Get metadata from fuzzer */
    if (get_metadata(&compartment, &instance, &type, &size) != 0) {
        break;
    }

    size = size % 8192;
    compartment = (compartment % 2) + 1;  // values 1, 2
    type = type % 22;                     // values 0-21

    /* Get payload */
    payload_size = get_payload(size, payload);

    /* Select endpoint */
    struct imsgbuf *target_ibuf = NULL;
    switch (compartment) {
        case 1:
            target_ibuf = &server_ibuf;
            break;
        case 2:
            target_ibuf = &logger_ibuf;
            break;
    }

    if (target_ibuf != NULL) {
        printf("compose! payload size is %lu, compartment ID is %d, type is %d\n",
               payload_size, compartment, type);
        ptr_check_skip(payload, payload_size);
        imsg_compose(target_ibuf, type, 0, 0, -1, payload, payload_size);
        imsg_flush(target_ibuf);
    }
}

imsg_compose(&server_ibuf, IMSG_EOM, 0, 0, -1, NULL, 0);
imsg_compose(&logger_ibuf, IMSG_EOM, 0, 0, -1, NULL, 0);
imsg_flush(&server_ibuf);
imsg_flush(&logger_ibuf);
```

### Converted Code Using Library

```c
#include "msg_generator.h"

/* Initialize communication endpoints (same as before) */
struct imsgbuf server_ibuf;
int server_fd = ps->ps_pipes[PROC_SERVER][0].pp_pipes[PROC_PARENT][0];
imsg_init(&server_ibuf, server_fd);

struct imsgbuf logger_ibuf;
int logger_fd = ps->ps_pipes[PROC_LOGGER][0].pp_pipes[PROC_PARENT][0];
imsg_init(&logger_ibuf, logger_fd);

/* Initialize the message generator interface */
struct msg_interface iface;
/* Initialize with 2 compartments and 22 message types (0-21) */
if (msg_interface_init(&iface, STDIN_FILENO, 2, 22) != MSG_GEN_SUCCESS) {
    errx(1, "Failed to initialize message interface");
}

/* Default 1:1 message type mapping is already set up (0->0, 1->1, ... 21->21) */
/* If you need custom mapping, use msg_interface_set_message_type() or msg_interface_set_message_types_batch() */

/* Register compartment endpoints (compartment 0 = server, compartment 1 = logger) */
msg_interface_set_endpoint(&iface, 0, &server_ibuf);
msg_interface_set_endpoint(&iface, 1, &logger_ibuf);

/* Set EOM message type */
msg_interface_set_eom_type(&iface, IMSG_EOM);

/* Generate and send messages */
struct msg_data msg;
int ret;

while ((ret = msg_generate(&iface, &msg)) == MSG_GEN_SUCCESS) {
    struct imsgbuf *target_ibuf = (struct imsgbuf *)msg.endpoint;

    if (target_ibuf != NULL) {
        /* Extract auxiliary data (e.g., pid and session ID) */
        uint32_t *aux_pid = (uint32_t *)&msg.aux_data[0];
        uint32_t *aux_session = (uint32_t *)&msg.aux_data[4];

        printf("compose! payload size is %u, compartment ID is %u, type is %u\n",
               msg.actual_payload_size, msg.compartment, msg.type);
        printf("  aux data: pid=%u, session=%u\n", *aux_pid, *aux_session);

        ptr_check_skip(msg.payload, msg.actual_payload_size);

        /* Send message with or without FD */
        /* Note: imsg_compose uses peerid parameter for pid, but aux_data can hold more */
        imsg_compose(target_ibuf, msg.type, *aux_pid, *aux_session,
                     msg.has_fd ? msg.fd : -1,
                     msg.payload, msg.actual_payload_size);
        imsg_flush(target_ibuf);

        /* Close the FD if it was created */
        if (msg.has_fd && msg.fd != -1) {
            close(msg.fd);
        }
    }
}

/* Send EOM messages to all compartments */
for (uint8_t i = 0; i < iface.num_compartments; i++) {
    struct msg_data eom_msg;
    if (msg_generate_eom(&iface, i, &eom_msg) == MSG_GEN_SUCCESS) {
        struct imsgbuf *target = (struct imsgbuf *)eom_msg.endpoint;
        if (target != NULL) {
            imsg_compose(target, eom_msg.type, 0, 0, -1, NULL, 0);
            imsg_flush(target);
        }
    }
}
```

## Conversion Insights

### What Changed

1. **No Manual Metadata Reading**: `get_metadata()` and `get_payload()` are replaced by `msg_generate()`

2. **No Manual Normalization**: The library handles modulo operations internally for equal probability

3. **No Switch Statement**: The library populates `msg.endpoint` automatically based on compartment

4. **Compartment Indexing**: Original code used 1-based (1, 2), library uses 0-based (0, 1)
   - Original compartment 1 → Library compartment 0
   - Original compartment 2 → Library compartment 1

5. **FD Support Added**: The library can now generate and send file descriptors with proper permissions

6. **Message Type Mapping**: If your application's message types don't start at 0, use batch mapping:
   ```c
   // For types like: 0, 1, 2, 3, 100, 101, 102...
   // First 4 are 1:1 (default)
   // Then set 4-6 to map to 100-102
   msg_interface_set_message_types_batch(&iface, 4, 3, 96);
   ```

7. **EOM Integration**: Instead of manually sending EOMs, use `msg_generate_eom()` with a loop
   - More maintainable: automatically handles all compartments
   - Consistent with message generation pattern
   - Receiving side can use `eom_counter_init_from_interface()` helper

### Benefits

1. **Cleaner Code**: No manual fuzzer input parsing or normalization
2. **FD Support**: Automatic creation of file descriptors with data and permissions
3. **Consistency**: Equal probability distribution guaranteed by modulo
4. **Reusability**: Same library works for different applications
5. **Safety**: Fixed-size arrays prevent allocation failures
6. **EOM Tracking**: Built-in counter for graceful termination when all compartments finish

## Using EOM Counter in Receiving Compartments

If you're writing code for a **receiving compartment** (e.g., the server or logger that receives messages), the EOM counter is automatically initialized when you call `msg_interface_init()`. Simply call `eom_counter_inc()` when you receive an EOM message:

```c
#include "msg_generator.h"

/* In your receiving compartment's initialization code */
void server_init(void) {
    /* If you initialized msg_interface, EOM counter is already set! */
    /* Default: expecting EOMs equal to num_compartments */

    /* Only call eom_counter_init() if you need a different value: */
    /* eom_counter_init(1);  // Override to expect just 1 EOM */
}

/* In your message dispatch loop */
void server_dispatch(struct imsg *imsg) {
    switch (imsg->hdr.type) {
        case IMSG_EOM:
            printf("Received EOM, shutting down\n");
            eom_counter_inc();  /* Will exit(0) when count reached */
            break;

        case IMSG_DATA:
            /* Handle data message */
            break;

        /* ... other message types ... */
    }
}
```

**Note**: The EOM counter uses `exit(0)` to terminate the program. This is suitable for fuzzing scenarios where clean shutdown is desired after all messages are processed.

## Fuzzer Input Format

The library expects fuzzer input in this binary format (73 bytes metadata per message):

```
Offset | Size | Field        | Normalization
-------|------|--------------|----------------------------------
0      | 1    | compartment  | % num_compartments
1      | 1    | instance     | (reserved, not used)
2      | 1    | type         | mapped via message_type_mapping[]
3      | 2    | size         | % MAX_MESSAGE_LENGTH
5      | 1    | has_fd       | % 2 (0 or 1)
6      | 1    | fd_perm      | (% 3) + 1 (1, 2, or 3)
7      | 2    | fd_data_len  | % MAX_MESSAGE_LENGTH
9      | 64   | aux_data     | Auxiliary data (no normalization)
```

**Important**: The library **requires** all 64 bytes of auxiliary data to be present. If the full 64 bytes cannot be read, `msg_generate()` returns `MSG_GEN_ERROR`.

Followed by:
- `size` bytes of message payload
- `fd_data_len` bytes of FD data (if `has_fd == 1`)

### Auxiliary Data Usage

The 64-byte `aux_data` buffer is intended for non-payload metadata that frameworks like `imsg` can send alongside messages. Common uses include:

- **Process ID (pid)**: 4 bytes (uint32_t or pid_t)
- **User/Group IDs**: 4-8 bytes each (uid_t, gid_t)
- **Session IDs**: 4 bytes
- **Custom application IDs**: Variable length
- **Timestamps**: 8 bytes (uint64_t)
- **Flags and control data**: 1-4 bytes

**Example layout for imsg-style metadata**:
```c
struct aux_metadata {
    uint32_t pid;           // Process ID (bytes 0-3)
    uint32_t uid;           // User ID (bytes 4-7)
    uint32_t gid;           // Group ID (bytes 8-11)
    uint32_t session_id;    // Session ID (bytes 12-15)
    char reserved[48];      // Reserved for future use (bytes 16-63)
};

// Access auxiliary data
struct aux_metadata *aux = (struct aux_metadata *)msg.aux_data;
printf("Message from pid %u\n", aux->pid);
```

## Advanced Usage

### Custom Message Type Ranges

If your application has non-contiguous message types:

```c
// Application has types: 0-10, 50-55, 100-120
msg_interface_set_message_types_batch(&iface, 0, 11, 0);    // 0-10 → 0-10
msg_interface_set_message_types_batch(&iface, 11, 6, 39);   // 11-16 → 50-55
msg_interface_set_message_types_batch(&iface, 17, 21, 83);  // 17-37 → 100-120
```

### Multiple Endpoints per Compartment

If you need instance-based routing:

```c
// Use the instance field in your code
if (msg.instance == 0) {
    // Route to first instance
} else {
    // Route to second instance
}
```

### Debugging

Check how many messages were generated:

```c
printf("Generated %u messages\n", iface.messages_generated);
```

## Error Handling

Always check return values:

```c
int ret = msg_generate(&iface, &msg);
if (ret == MSG_GEN_EOF) {
    // Normal termination - no more fuzzer input
} else if (ret == MSG_GEN_ERROR) {
    // Error occurred - check errno or add logging
    errx(1, "Message generation failed");
}
```

## Memory Management

The library uses **no dynamic allocation**. All structures can be stack-allocated:

```c
struct msg_interface iface;  // ~66KB on stack
struct msg_data msg;         // ~131KB on stack
```

For large structures, consider static allocation or careful stack management.

## Thread Safety

The library is **not thread-safe**. Each thread should have its own `msg_interface` and `msg_data` instances if used in multi-threaded contexts.

## Compilation

### Using the Makefile

The project includes a Makefile that builds the library:

```bash
# Build the message generator static library
make libmsg_generator.a

# Or build everything (including buffer checker and EOM libraries)
make all

# Clean build artifacts
make clean
```

### Manual Compilation

If you need to build manually:

```bash
# Compile the source
clang -fPIC -Wall -Wextra -O0 -g -c msg_generator.c -o msg_generator.o

# Create static library
ar rcs libmsg_generator.a msg_generator.o

# Link with your application
clang your_app.c -L. -lmsg_generator -o your_app
```

### Integration Notes

- The library is built as a **static library** (`.a`) for source-level compatibility across versions
- The library includes integrated EOM counter functionality (no need to link separately)
- No external dependencies except standard C library and POSIX sockets

## Summary

The Message Generator Library (with integrated EOM support) abstracts away the complexity of:
- Reading and parsing fuzzer input
- Normalizing values for equal probability
- Managing message type mappings
- Creating file descriptors with proper permissions
- Routing messages to correct endpoints
- Generating End-of-Message signals for graceful termination
- Tracking received EOMs in receiving compartments

This allows you to focus on the application logic rather than fuzzer input handling and process coordination.
