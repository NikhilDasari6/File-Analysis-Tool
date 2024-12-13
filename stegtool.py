#!/usr/bin/env python3
import os
import magic
import argparse
import string

def detect_file(file_path):
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' does not exist.")
        return

    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)

    print(f"File: {file_path}")
    print(f"Type: {mime_type}")


def extract_text(file_path):
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' does not exist.")
        return

    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        readable_text = ''.join(
            chr(c) if chr(c) in string.printable else '' for c in content
        )
        
        if readable_text.strip():
            print(f"Extracted Text from {file_path}:\n")
            print(readable_text)
        else:
            print(f"No readable text found in {file_path}.")
    except Exception as e:
        print(f"Error: Could not read the file '{file_path}'. {e}")


def main():
    parser = argparse.ArgumentParser(description="A CLI tool for file detection and text extraction.")
    
    parser.add_argument(
        "-d",
        metavar="FILE",
        help="Detect the MIME type of the specified file."
    )

    parser.add_argument(
        "-t",
        metavar="FILE",
        help="Extract readable ASCII or Unicode text from the specified file."
    )

    args = parser.parse_args()

    if args.d:
        detect_file(args.d)
    elif args.t:
        extract_text(args.t)
    else:
        print("No valid options provided. Use --help for usage information.")


if __name__ == "__main__":
    main()

