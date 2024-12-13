#!/usr/bin/env python3

import argparse
import magic
import re

def detect_file_type(file_path):
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        print(f"File type: {file_type}")
    except Exception as e:
        print(f"Error detecting file type: {e}")

def extract_readable_text(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            readable_text = "".join(
                chr(byte) if 32 <= byte < 127 or 160 <= byte <= 255 else ""
                for byte in content
            )
            print("Readable Text:")
            print(readable_text)
    except Exception as e:
        print(f"Error extracting readable text: {e}")

def hex_dump(file_path, bytes_per_line=16):
    try:
        with open(file_path, 'rb') as file:
            offset = 0
            while chunk := file.read(bytes_per_line):
                hex_values = " ".join(f"{byte:02x}" for byte in chunk)
                ascii_values = "".join(
                    chr(byte) if 32 <= byte < 127 else "." for byte in chunk
                )
                print(f"{offset:08x}  {hex_values:<{bytes_per_line*3}}  |{ascii_values}|")
                offset += bytes_per_line
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except PermissionError:
        print(f"Error: Permission denied for file '{file_path}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def reverse_hex_dump(hex_dump_path, output_file_path):
    try:
        with open(hex_dump_path, 'r') as hex_file, open(output_file_path, 'wb') as output_file:
            for line in hex_file:
                # Extract hex values from the line
                match = re.match(r"^[0-9a-fA-F]+(?:\s+)([0-9a-fA-F\s]+)", line)
                if match:
                    hex_values = match.group(1).strip().split()
                    # Convert hex values to bytes and write to output
                    output_file.write(bytes(int(byte, 16) for byte in hex_values))
        print(f"Binary file successfully created: {output_file_path}")
    except FileNotFoundError:
        print(f"Error: The hex dump file '{hex_dump_path}' does not exist.")
    except Exception as e:
        print(f"Error reversing hex dump: {e}")

def main():
    """
    Main function to handle CLI arguments and run the appropriate features.
    """
    parser = argparse.ArgumentParser(
        description="CLI Tool with file detection, readable text extraction, hex dump, and reverse hex dump features."
    )
    parser.add_argument(
        "-d", "--detect",
        metavar="FILE",
        help="Detect the file type of the specified file."
    )
    parser.add_argument(
        "-t", "--text",
        metavar="FILE",
        help="Extract readable ASCII/Unicode text from the specified file."
    )
    parser.add_argument(
        "-x", "--hex-dump",
        metavar="FILE",
        help="Generate a hex dump of the specified file."
    )
    parser.add_argument(
        "-r", "--reverse-hex",
        nargs=2,
        metavar=("HEX_FILE", "OUTPUT_FILE"),
        help="Reverse a hex dump back into a binary file."
    )
    parser.add_argument(
        "-b", "--bytes-per-line",
        type=int,
        default=16,
        help="Number of bytes to display per line in the hex dump (default: 16)."
    )

    args = parser.parse_args()

    if args.detect:
        detect_file_type(args.detect)
    elif args.text:
        extract_readable_text(args.text)
    elif args.hex_dump:
        hex_dump(args.hex_dump, args.bytes_per_line)
    elif args.reverse_hex:
        reverse_hex_dump(*args.reverse_hex)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

