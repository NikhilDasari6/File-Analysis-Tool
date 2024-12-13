#!/usr/bin/env python3

import argparse
import magic

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

def main():
    parser = argparse.ArgumentParser(
        description="CLI Tool with file detection, readable text extraction, and hex dump features."
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
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

