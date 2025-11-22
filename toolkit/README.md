# Message Generator Toolkit

This toolkit provides two Python utilities for working with binary message files used in fuzzing inter-compartment communication.

## Tools

### 1. Message Generator (`msg_gen_tool.py`)

Generates binary messages according to the `msg_data` structure format defined in the Message Generator Library.

#### Features

- Generate structured binary messages with all required fields
- Support for auxiliary data (64 bytes) with simple uint32_t input format
- Support for file descriptors with permissions
- Read payload and FD data from external files
- Interactive mode for guided input
- Command-line mode for scripting

#### Usage

**Interactive Mode** (prompts for all inputs):
```bash
./msg_gen_tool.py
```

**Command-Line Mode**:
```bash
# Message with file descriptor
./msg_gen_tool.py -c 0 -i 0 -t 5 --has-fd 1 --fd-perm 3 \
    --aux "100 200 300" \
    --payload payload.bin --fd-data fddata.bin \
    -o message.bin

# Message without file descriptor
./msg_gen_tool.py -c 1 -i 0 -t 10 --has-fd 0 \
    --aux "0" --payload data.bin -o msg.bin

# Empty payload (metadata only)
./msg_gen_tool.py -c 0 -i 0 -t 1 --has-fd 0 --aux "42" -o minimal.bin
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-c, --compartment` | 0-255 | Target compartment ID |
| `-i, --instance` | 0-255 | Instance ID (typically 0) |
| `-t, --type` | 0-255 | Message type |
| `--has-fd` | 0 or 1 | Whether message includes a file descriptor |
| `--fd-perm` | 1, 2, or 3 | FD permissions: 1=read, 2=write, 3=both (required if has-fd=1) |
| `--aux` | string | Auxiliary data as space-separated uint32_t values (e.g., "10 20 30") or "0" for zeros |
| `--payload` | path | File containing message payload (optional, can be omitted for empty payload) |
| `--fd-data` | path | File containing FD data (optional, only used if has-fd=1) |
| `-o, --output` | path | Output file path (required) |

#### Auxiliary Data Format

The `--aux` parameter accepts space-separated uint32_t values:
- `--aux "0"` - All 64 bytes set to zero
- `--aux "100"` - First 4 bytes = 100, rest are zeros
- `--aux "100 200 300"` - First 12 bytes contain three uint32_t values (100, 200, 300), rest are zeros

Each value is packed as a native-endian uint32_t.

#### Message Structure

Generated messages follow this binary format (total: 73 + payload_size + fd_data_size bytes):

```
Offset | Size | Field
-------|------|------------------
0      | 1    | compartment
1      | 1    | instance
2      | 1    | type
3      | 2    | size (payload length)
5      | 1    | has_fd
6      | 1    | fd_perm
7      | 2    | fd_data_len
9      | 64   | aux_data
73     | N    | payload
73+N   | M    | fd_data
```

All multi-byte fields use native byte order.

#### Examples

Generate a message for compartment 0, type 5, with FD:
```bash
echo "Hello World" > payload.txt
echo "FD content" > fd.txt
./msg_gen_tool.py -c 0 -i 0 -t 5 --has-fd 1 --fd-perm 3 \
    --aux "1000 2000" --payload payload.txt --fd-data fd.txt \
    -o msg.bin
```

Generate multiple messages in a script:
```bash
for i in 0 1 2; do
    ./msg_gen_tool.py -c $i -i 0 -t 10 --has-fd 0 \
        --aux "$((i * 100))" --payload data.bin \
        -o "msg_$i.bin"
done
```

### 2. File Concatenation Tool (`concat_files.py`)

Concatenates two binary files into a third file. Useful for combining multiple messages into a single input file.

#### Usage

```bash
./concat_files.py file1.bin file2.bin output.bin
```

#### Examples

Combine two messages:
```bash
./concat_files.py msg1.bin msg2.bin combined_messages.bin
```

Build a sequence of messages:
```bash
./concat_files.py msg1.bin msg2.bin temp.bin
./concat_files.py temp.bin msg3.bin final.bin
```

## Installation

Both tools are standalone Python 3 scripts with no external dependencies.

Make them executable:
```bash
chmod +x msg_gen_tool.py concat_files.py
```

## Integration with Message Generator Library

These tools generate files that can be used as input to programs using the Message Generator Library. The binary format matches the expected fuzzer input format.

Example workflow:
1. Generate individual messages with `msg_gen_tool.py`
2. Concatenate them with `concat_files.py` if needed
3. Feed the result to your fuzzer or test harness via stdin

```bash
# Generate two messages
./msg_gen_tool.py -c 0 -i 0 -t 5 --has-fd 0 --aux "0" --payload p1.bin -o msg1.bin
./msg_gen_tool.py -c 1 -i 0 -t 10 --has-fd 1 --fd-perm 1 --aux "100" --payload p2.bin --fd-data fd.bin -o msg2.bin

# Combine them
./concat_files.py msg1.bin msg2.bin input.bin

# Use as fuzzer input
cat input.bin | ./your_fuzzer_program
```

## Notes

- Both tools handle binary data correctly
- Empty files are treated as zero-length payloads
- The message generator automatically calculates `size` and `fd_data_len` from the input files
- All byte values are masked to appropriate ranges (e.g., compartment & 0xFF)
- Use native byte order for compatibility with the C library

## See Also

- `../MSG_GENERATOR_GUIDE.md` - Complete guide to the Message Generator Library
- `../msg_generator.h` - C library header file
