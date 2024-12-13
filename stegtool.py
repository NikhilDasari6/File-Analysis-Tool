#!/usr/bin/env python3
import os
import magic

def detect_file(file_path):
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' does not exist.")
        return

    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)

    print(f"File: {file_path}")
    print(f"Type: {mime_type}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Detect the MIME type of a file.")
    parser.add_argument("file", help="Path to the file to analyze.")
    args = parser.parse_args()

    detect_file(args.file)

