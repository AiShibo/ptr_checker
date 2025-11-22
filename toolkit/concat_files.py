#!/usr/bin/env python3
"""
File Concatenation Tool

This tool takes two file names and concatenates them into a third file.
"""

import sys
import argparse


def concatenate_files(file1, file2, output):
    """Concatenate file1 and file2 into output file."""
    try:
        # Read first file
        with open(file1, 'rb') as f1:
            data1 = f1.read()
            size1 = len(data1)

        # Read second file
        with open(file2, 'rb') as f2:
            data2 = f2.read()
            size2 = len(data2)

        # Write concatenated data to output
        with open(output, 'wb') as fout:
            fout.write(data1)
            fout.write(data2)

        print(f"Files concatenated successfully!")
        print(f"  {file1}: {size1} bytes")
        print(f"  {file2}: {size2} bytes")
        print(f"  {output}: {size1 + size2} bytes (total)")

    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"Error: Permission denied - {e.filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Concatenate two files into a third file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Concatenate file1.bin and file2.bin into output.bin
  %(prog)s file1.bin file2.bin output.bin

  # Concatenate message files
  %(prog)s msg1.dat msg2.dat combined.dat
        """)

    parser.add_argument('file1', help='First input file')
    parser.add_argument('file2', help='Second input file')
    parser.add_argument('output', help='Output file (will be overwritten if exists)')

    args = parser.parse_args()

    concatenate_files(args.file1, args.file2, args.output)


if __name__ == '__main__':
    main()
