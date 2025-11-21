# FD Send/Receive Tests

This directory contains tests for the `msg_generator` library's file descriptor (FD) passing functionality.

## Overview

The test demonstrates that when the `msg_generator` library receives fuzzer input indicating a message should include a file descriptor, it:

1. Creates a UNIX socketpair with appropriate permissions (read/write/both)
2. Writes the specified data to one end of the socketpair
3. Returns the other end as the FD in the `msg_data` structure
4. The receiving program can successfully read the expected data from that FD

## Test Components

### `fd_receiver.c`
A standalone program that:
- Receives a file descriptor over a UNIX socket (using `SCM_RIGHTS`)
- Reads data from the received FD
- Verifies the data matches the expected pattern (`TEST_DATA_` prefix)
- Reports success or failure

### `fd_sender_test.c`
The test harness that:
- Creates synthetic fuzzer input specifying a message with an FD
- Uses the `msg_generator` library to generate a message from that input
- Forks a child process to run `fd_receiver`
- Sends the generated FD to the receiver via UNIX socket
- Waits for the receiver to validate the data

### Fuzzer Input Format

The test creates the following fuzzer input (9 bytes metadata + payloads):

```
Metadata (9 bytes):
  - compartment:  0
  - instance:     0
  - type:         42
  - size:         100 (message payload size)
  - has_fd:       1 (yes, include FD)
  - fd_perm:      3 (read+write permissions)
  - fd_data_len:  50 (FD data size)

Message Payload (100 bytes):
  - "MESSAGE_PAYLOAD_DATA" + padding

FD Data (50 bytes):
  - "TEST_DATA_via_FD" + padding
```

## Building and Running

### Build all tests:
```bash
make
```

### Build and run the test:
```bash
make test
```

### Clean build artifacts:
```bash
make clean
```

## Expected Output

When the test runs successfully, you should see output like:

```
=== FD Sender/Receiver Test ===

[SENDER] Initializing message interface...
[SENDER] Generating message from fuzzer input...
[SENDER] Message generated successfully:
[SENDER]   Compartment: 0
[SENDER]   Type: 42
[SENDER]   Payload size: 100
[SENDER]   Has FD: 1
[SENDER]   FD permissions: 3 (1=read, 2=write, 3=both)
[SENDER]   FD data size: 50
[SENDER]   FD number: 5
[SENDER] FD data (first 32 bytes): 54 45 53 54 5f 44 41 54 ...
[SENDER] Sending FD 5 to receiver...
[SENDER] FD sent successfully

=== FD Receiver Test Program ===
[RECEIVER] Control socket FD: 6
[RECEIVER] Waiting to receive FD...
[RECEIVER] Received FD: 5
[RECEIVER] Reading data from FD 5...
[RECEIVER] Read 50 bytes from FD
[RECEIVER] First 50 bytes (hex): 54 45 53 54 5f 44 41 54 ...
[RECEIVER] ✓ Data verification PASSED
[RECEIVER] Test PASSED

[SENDER] Waiting for receiver to finish...
[SENDER] Receiver exited with code 0

=== Test PASSED ===
```

## How It Works

1. **Test Setup**: The sender creates a UNIX socketpair for control communication and synthetic fuzzer input

2. **Fork**: The process forks into sender (parent) and receiver (child)

3. **Message Generation**: The sender uses `msg_generate()` which:
   - Reads the 9-byte metadata from fuzzer input
   - Normalizes values (compartment, type, sizes)
   - Reads 100 bytes of message payload
   - Sees `has_fd=1`, so creates a UNIX socketpair
   - Reads 50 bytes of FD data and writes it to one end of the socketpair
   - Returns the other end as `msg.fd`

4. **FD Transfer**: The sender passes `msg.fd` to the receiver over the control socket using `SCM_RIGHTS`

5. **Verification**: The receiver reads from the FD and verifies it contains "TEST_DATA_via_FD"

6. **Cleanup**: Both processes close their FDs and exit

## What This Tests

- ✓ The `msg_generator` library correctly interprets `has_fd=1` in fuzzer input
- ✓ The library creates a valid UNIX socketpair for FD data
- ✓ The library writes the specified FD data to the socketpair
- ✓ The returned FD can be passed to another process
- ✓ The receiving process can read the expected data from the FD
- ✓ The FD permissions are set correctly (read+write)

## Integration with ptr_checker

This test validates the FD functionality that would be used in fuzzing scenarios where:

1. A fuzzer-driven parent process generates messages with FDs
2. Those messages (and FDs) are sent to child compartments
3. The child compartments receive the FDs and read data from them
4. The `ptr_checker` library validates that data doesn't contain pointers

The test demonstrates the complete pipeline works correctly for FD-based communication between compartments.
