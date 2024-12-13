#!/usr/bin/env python3
import os
import magic
import argparse

def detect_file(file_path):
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' does not exist.")
        return

    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)

    print(f"File: {file_path}")
    print(f"Type: {mime_type}")


def main():
    """
    Main function to parse command-line arguments and execute the tool.
    """
    parser = argparse.ArgumentParser(
        description="A CLI tool with file detection functionality."
    )
    
    parser.add_argument(
        "-d",
        metavar="FILE",
        help="Detect the MIME type of the specified file."
    )

    args = parser.parse_args()

    if args.d:
        detect_file(args.d)
    else:
        print("No valid options provided. Use --help for usage information.")


if __name__ == "__main__":
    main()

