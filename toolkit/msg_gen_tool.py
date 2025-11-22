#!/usr/bin/env python3
"""
Message Generator Tool

This tool generates binary messages according to the msg_data structure format.
It prompts the user for all fields and reads payload/fd_data from files.
It can also explain the contents of a generated message file.
"""

import struct
import sys
import os
import argparse


def read_file_or_empty(filepath):
    """Read file contents, return empty bytes if file doesn't exist or is empty."""
    if not filepath or not os.path.exists(filepath):
        return b''

    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Warning: Could not read file {filepath}: {e}", file=sys.stderr)
        return b''


def parse_aux_data(aux_input):
    """
    Parse auxiliary data input.
    User can input space-separated uint32_t values like "10 20 30"
    Each number is interpreted as uint32_t, remaining bytes are set to 0.
    Returns 64 bytes.
    """
    aux_bytes = bytearray(64)  # Initialize with zeros

    if not aux_input or aux_input == "0":
        return bytes(aux_bytes)

    # Split the input and parse as uint32_t values
    try:
        values = [int(x.strip()) for x in aux_input.split() if x.strip()]

        offset = 0
        for val in values:
            if offset + 4 > 64:
                print(f"Warning: Too many aux_data values, truncating at 64 bytes", file=sys.stderr)
                break

            # Pack as uint32_t (native byte order)
            struct.pack_into('=I', aux_bytes, offset, val & 0xFFFFFFFF)
            offset += 4

    except ValueError as e:
        print(f"Error parsing aux_data: {e}", file=sys.stderr)
        sys.exit(1)

    return bytes(aux_bytes)


def interactive_mode():
    """Interactive session to gather all necessary data from user."""
    print("=== Message Generator - Interactive Mode ===\n")

    # Get metadata
    compartment = int(input("Enter compartment ID (uint8): "))
    instance = int(input("Enter instance ID (uint8, typically 0): "))
    msg_type = int(input("Enter message type (uint8): "))

    # Get FD metadata
    has_fd_input = input("Does message have a file descriptor? (0/1): ")
    has_fd = int(has_fd_input)

    fd_perm = 0
    fd_data_file = ""
    if has_fd == 1:
        print("FD permissions: 1=read, 2=write, 3=both")
        fd_perm = int(input("Enter FD permissions (1-3): "))
        fd_data_file = input("Enter file path for FD data (or empty for no data): ").strip()

    # Get auxiliary data
    print("\nAuxiliary data (64 bytes):")
    print("Enter space-separated uint32_t values (e.g., '10 20 30')")
    print("Or enter '0' for all zeros")
    aux_input = input("Aux data: ").strip()

    # Get payload file
    payload_file = input("\nEnter file path for message payload (or empty for no payload): ").strip()

    # Get output file
    output_file = input("Enter output file path: ").strip()

    return {
        'compartment': compartment,
        'instance': instance,
        'msg_type': msg_type,
        'has_fd': has_fd,
        'fd_perm': fd_perm,
        'aux_data_input': aux_input,
        'payload_file': payload_file,
        'fd_data_file': fd_data_file,
        'output_file': output_file
    }


def generate_message(compartment, instance, msg_type, has_fd, fd_perm, aux_data_input,
                     payload_file, fd_data_file, output_file):
    """Generate the binary message according to the format."""

    # Read payload and fd_data from files
    payload = read_file_or_empty(payload_file)
    fd_data = read_file_or_empty(fd_data_file) if has_fd else b''

    # Calculate sizes
    size = len(payload)
    fd_data_len = len(fd_data)

    # Validate sizes
    if size > 65535:
        print(f"Error: Payload size {size} exceeds maximum 65535 bytes", file=sys.stderr)
        sys.exit(1)

    if fd_data_len > 65535:
        print(f"Error: FD data size {fd_data_len} exceeds maximum 65535 bytes", file=sys.stderr)
        sys.exit(1)

    # Parse auxiliary data
    aux_data = parse_aux_data(aux_data_input)

    # Validate fields
    compartment = compartment & 0xFF
    instance = instance & 0xFF
    msg_type = msg_type & 0xFF
    has_fd = has_fd & 0xFF
    fd_perm = fd_perm & 0xFF

    # Build the message
    # Format: compartment(1) + instance(1) + type(1) + size(2) + has_fd(1) + fd_perm(1) + fd_data_len(2) + aux_data(64)
    # Use native byte order (=) for compatibility with C code
    header = struct.pack('=BBBHBBH',
                        compartment,
                        instance,
                        msg_type,
                        size,
                        has_fd,
                        fd_perm,
                        fd_data_len)

    # Combine: header + aux_data + payload + fd_data
    message = header + aux_data + payload + fd_data

    # Write to output file
    try:
        with open(output_file, 'wb') as f:
            f.write(message)

        print(f"\nMessage generated successfully!")
        print(f"  Output file: {output_file}")
        print(f"  Total size: {len(message)} bytes")
        print(f"    - Header: 9 bytes")
        print(f"    - Aux data: 64 bytes")
        print(f"    - Payload: {size} bytes")
        print(f"    - FD data: {fd_data_len} bytes")

    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)


def explain_message(input_file):
    """
    Read a generated message file and explain all its values.

    Message format (73+ bytes):
    - compartment (1 byte)
    - instance (1 byte)
    - type (1 byte)
    - size (2 bytes)
    - has_fd (1 byte)
    - fd_perm (1 byte)
    - fd_data_len (2 bytes)
    - aux_data (64 bytes)
    - payload (size bytes)
    - fd_data (fd_data_len bytes, if has_fd=1)
    """
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file {input_file}: {e}", file=sys.stderr)
        sys.exit(1)

    # Check minimum size
    if len(data) < 73:
        print(f"Error: File too small ({len(data)} bytes). Minimum is 73 bytes (header + aux_data).", file=sys.stderr)
        sys.exit(1)

    # Parse header (9 bytes)
    compartment, instance, msg_type, size, has_fd, fd_perm, fd_data_len = struct.unpack('=BBBHBBH', data[0:9])

    # Parse auxiliary data (64 bytes)
    aux_data = data[9:73]

    # Calculate expected total size
    expected_size = 73 + size + (fd_data_len if has_fd else 0)
    actual_size = len(data)

    # Extract payload
    payload_start = 73
    payload_end = 73 + size

    if payload_end > actual_size:
        print(f"Warning: File size ({actual_size}) is smaller than expected for payload (needs {payload_end})", file=sys.stderr)
        payload = data[payload_start:actual_size]
        actual_payload_size = len(payload)
        fd_data = b''
        actual_fd_size = 0
    else:
        payload = data[payload_start:payload_end]
        actual_payload_size = len(payload)

        # Extract FD data if present
        if has_fd:
            fd_start = payload_end
            fd_end = fd_start + fd_data_len

            if fd_end > actual_size:
                print(f"Warning: File size ({actual_size}) is smaller than expected for FD data (needs {fd_end})", file=sys.stderr)
                fd_data = data[fd_start:actual_size]
                actual_fd_size = len(fd_data)
            else:
                fd_data = data[fd_start:fd_end]
                actual_fd_size = len(fd_data)
        else:
            fd_data = b''
            actual_fd_size = 0

    # Print explanation
    print("=" * 70)
    print("MESSAGE EXPLANATION")
    print("=" * 70)
    print(f"\nFile: {input_file}")
    print(f"Total file size: {actual_size} bytes")
    print(f"Expected size: {expected_size} bytes")

    if actual_size != expected_size:
        print(f"⚠ SIZE MISMATCH: File has {actual_size - expected_size:+d} bytes")

    print("\n" + "-" * 70)
    print("METADATA (9 bytes)")
    print("-" * 70)
    print(f"Compartment ID:      {compartment} (0x{compartment:02x})")
    print(f"  → Target compartment after normalization: compartment % num_compartments")
    print(f"\nInstance ID:         {instance} (0x{instance:02x})")
    print(f"  → Reserved field, typically 0")
    print(f"\nMessage Type:        {msg_type} (0x{msg_type:02x})")
    print(f"  → Actual type after mapping: message_type_mapping[type % num_message_types]")
    print(f"\nPayload Size:        {size} bytes")
    print(f"  → Normalized to: size % MAX_MESSAGE_LENGTH (65535)")
    print(f"  → Actual payload read: {actual_payload_size} bytes")

    print("\n" + "-" * 70)
    print("FILE DESCRIPTOR METADATA")
    print("-" * 70)
    print(f"Has FD:              {has_fd}")
    print(f"  → Normalized to: has_fd % 2 (0 or 1)")

    if has_fd:
        fd_perm_str = {1: "read-only", 2: "write-only", 3: "read-write"}.get(fd_perm, "invalid")
        print(f"\nFD Permissions:      {fd_perm} ({fd_perm_str})")
        print(f"  → Normalized to: (fd_perm % 3) + 1")
        print(f"    1 = read-only, 2 = write-only, 3 = read-write")
        print(f"\nFD Data Length:      {fd_data_len} bytes")
        print(f"  → Normalized to: fd_data_len % MAX_MESSAGE_LENGTH (65535)")
        print(f"  → Actual FD data read: {actual_fd_size} bytes")

        if has_fd and fd_data_len > 0:
            print(f"\n  A UNIX socketpair will be created with {fd_perm_str} permissions.")
            print(f"  FD data will be written to one end for the receiver to read.")
    else:
        print("  → No file descriptor will be created")
        print(f"\nFD Permissions:      {fd_perm} (ignored, has_fd=0)")
        print(f"FD Data Length:      {fd_data_len} (ignored, has_fd=0)")

    print("\n" + "-" * 70)
    print("AUXILIARY DATA (64 bytes)")
    print("-" * 70)
    print("This data is NOT normalized - fuzzer controls it directly.")
    print("Common uses: process IDs, user/group IDs, session IDs, timestamps, flags\n")

    # Try to interpret as uint32_t values
    num_u32 = 64 // 4
    u32_values = struct.unpack(f'={num_u32}I', aux_data)

    print("Interpreted as uint32_t values:")
    for i in range(0, num_u32, 4):
        values = u32_values[i:i+4]
        bytes_range = f"[{i*4:2d}-{(i+4)*4-1:2d}]"
        values_str = "  ".join(f"{v:10d}" for v in values)
        hex_str = "  ".join(f"0x{v:08x}" for v in values)
        print(f"  Bytes {bytes_range}: {values_str}")
        print(f"                  {hex_str}")

    # Check if all zeros
    if all(b == 0 for b in aux_data):
        print("\n  → All auxiliary data is zero")

    # Show raw hex dump for first 32 bytes
    print("\nRaw hex dump (first 32 bytes):")
    for i in range(0, min(32, 64), 16):
        hex_part = ' '.join(f'{b:02x}' for b in aux_data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in aux_data[i:i+16])
        print(f"  {i:04x}: {hex_part:<48s}  {ascii_part}")

    print("\n" + "-" * 70)
    print("MESSAGE PAYLOAD")
    print("-" * 70)
    print(f"Declared size:       {size} bytes")
    print(f"Actual size read:    {actual_payload_size} bytes")

    if actual_payload_size == 0:
        print("  → No payload data")
    else:
        print(f"\nFirst {min(128, actual_payload_size)} bytes (hex):")
        for i in range(0, min(128, actual_payload_size), 16):
            chunk = payload[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"  {i:04x}: {hex_part:<48s}  {ascii_part}")

        if actual_payload_size > 128:
            print(f"  ... ({actual_payload_size - 128} more bytes)")

    if has_fd and fd_data_len > 0:
        print("\n" + "-" * 70)
        print("FILE DESCRIPTOR DATA")
        print("-" * 70)
        print(f"Declared size:       {fd_data_len} bytes")
        print(f"Actual size read:    {actual_fd_size} bytes")

        if actual_fd_size == 0:
            print("  → No FD data")
        else:
            print(f"\nFirst {min(128, actual_fd_size)} bytes (hex):")
            for i in range(0, min(128, actual_fd_size), 16):
                chunk = fd_data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"  {i:04x}: {hex_part:<48s}  {ascii_part}")

            if actual_fd_size > 128:
                print(f"  ... ({actual_fd_size - 128} more bytes)")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"This message will be sent to compartment {compartment} (after normalization)")
    print(f"Message type {msg_type} will be mapped through message_type_mapping[]")
    print(f"Total payload size: {actual_payload_size} bytes")
    if has_fd:
        print(f"Includes file descriptor with {fd_perm_str} permissions")
        print(f"FD will contain {actual_fd_size} bytes of data")
    else:
        print(f"No file descriptor attached")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='Generate and explain binary messages for fuzzing inter-compartment communication',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (generate)
  %(prog)s

  # Command-line mode with all parameters (generate)
  %(prog)s -c 0 -i 0 -t 5 --has-fd 1 --fd-perm 3 \\
           --aux "100 200 300" \\
           --payload payload.bin --fd-data fddata.bin \\
           -o message.bin

  # Message without FD (generate)
  %(prog)s -c 1 -i 0 -t 10 --has-fd 0 \\
           --aux "0" --payload data.bin -o msg.bin

  # Explain a generated message file
  %(prog)s --explain message.bin
        """)

    parser.add_argument('--explain', type=str, metavar='FILE',
                       help='Explain the contents of a generated message file')
    parser.add_argument('-c', '--compartment', type=int, help='Target compartment ID (0-255)')
    parser.add_argument('-i', '--instance', type=int, help='Instance ID (0-255, typically 0)')
    parser.add_argument('-t', '--type', type=int, help='Message type (0-255)')
    parser.add_argument('--has-fd', type=int, choices=[0, 1], help='Has file descriptor (0 or 1)')
    parser.add_argument('--fd-perm', type=int, choices=[1, 2, 3],
                       help='FD permissions: 1=read, 2=write, 3=both')
    parser.add_argument('--aux', type=str, default='0',
                       help='Auxiliary data as space-separated uint32_t values (e.g., "10 20 30") or "0" for zeros')
    parser.add_argument('--payload', type=str, help='File containing message payload')
    parser.add_argument('--fd-data', type=str, help='File containing FD data (if has_fd=1)')
    parser.add_argument('-o', '--output', type=str, help='Output file path')

    args = parser.parse_args()

    # Check if we should explain a message file
    if args.explain:
        explain_message(args.explain)
        return

    # Check if we should run in interactive mode
    if len(sys.argv) == 1:
        # No arguments provided - interactive mode
        params = interactive_mode()
        generate_message(**params)
    else:
        # Command-line mode - validate all required parameters
        required_params = ['compartment', 'instance', 'type', 'has_fd', 'output']
        missing = [p for p in required_params if getattr(args, p) is None]

        if missing:
            parser.error(f"Missing required arguments in command-line mode: {', '.join('--' + p for p in missing)}")

        if args.has_fd == 1 and args.fd_perm is None:
            parser.error("--fd-perm is required when --has-fd=1")

        generate_message(
            compartment=args.compartment,
            instance=args.instance,
            msg_type=args.type,
            has_fd=args.has_fd,
            fd_perm=args.fd_perm if args.fd_perm else 0,
            aux_data_input=args.aux,
            payload_file=args.payload if args.payload else '',
            fd_data_file=args.fd_data if args.fd_data else '',
            output_file=args.output
        )


if __name__ == '__main__':
    main()
