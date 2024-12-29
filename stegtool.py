#!/usr/bin/env python3
import argparse
import os
from PIL import Image
import numpy as np

def detect_file_type_with_magic_bytes(file_path):
    """
    Detect the type of a file based on its magic bytes.
    """
    # Dictionary of magic bytes and their corresponding file types
    magic_bytes = {
        # Image files
        b"\xFF\xD8\xFF": "JPEG Image",
        b"\x89PNG\r\n\x1A\n": "PNG Image",
        b"GIF87a": "GIF Image (87a)",
        b"GIF89a": "GIF Image (89a)",
        b"\x42\x4D": "BMP Image",
        b"\x00\x00\x01\x00": "ICO Image",
        
        # Document files
        b"%PDF-": "PDF Document",
        b"\x50\x4B\x03\x04": "ZIP Archive (or Office File)",
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "Microsoft Office (Old Format)",
        b"PK\x03\x04": "Microsoft Office/OpenXML",
        b"\x25\x21": "PostScript File",

        # Video and audio files
        b"RIFF....AVI ": "AVI Video",
        b"\x1A\x45\xDF\xA3": "MKV Video",
        b"\x00\x00\x01\xBA": "MPEG Video",
        b"\x00\x00\x01\xB3": "MPEG Video",
        b"\x49\x44\x33": "MP3 Audio",
        b"OggS": "OGG Audio",
        b"\x66\x4C\x61\x43": "FLAC Audio",
        b"\x52\x49\x46\x46": "WAV or AVI File",

        # Executable files
        b"\x4D\x5A": "Windows Executable (EXE/DLL)",
        b"\x7F\x45\x4C\x46": "ELF Executable",
        b"\xCA\xFE\xBA\xBE": "Java Class File",
        b"\x50\x4B\x03\x04": "JAR File (ZIP Archive)",

        # Archive files
        b"\x1F\x8B": "GZIP Archive",
        b"7z\xBC\xAF\x27\x1C": "7-Zip Archive",
        b"\x42\x5A\x68": "BZIP2 Archive",
        b"PK\x03\x04": "ZIP Archive",
        b"\x52\x61\x72\x21\x1A\x07\x00": "RAR Archive",

        # Others
        b"\xEF\xBB\xBF": "UTF-8 BOM",
        b"\xFE\xFF": "UTF-16 BE BOM",
        b"\xFF\xFE": "UTF-16 LE BOM",
        b"\x23\x21": "Linux Shell Script",
        b"\x3C\x3F\x78\x6D\x6C": "XML File",
    }

    try:
        with open(file_path, "rb") as f:
            # Read the first 16 bytes to match with magic numbers
            file_header = f.read(16)

        # Match file_header against known magic numbers
        for magic, file_type in magic_bytes.items():
            if file_header.startswith(magic):
                return file_type

        # If no match is found
        return "Unknown file type or unsupported magic bytes"
    except Exception as e:
        return f"Error detecting file type: {e}"

def extract_ascii_strings(file_path, min_length=4):
    """
    Extract readable ASCII strings from a file.
    
    Args:
        file_path (str): Path to the file to analyze.
        min_length (int): Minimum length of the ASCII strings to extract.
        
    Returns:
        list: A list of readable ASCII strings.
    """
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Find sequences of printable ASCII characters
        ascii_strings = []
        current_string = ""

        for byte in content:
            char = chr(byte)
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string += char
            else:
                if len(current_string) >= min_length:
                    ascii_strings.append(current_string)
                current_string = ""  # Reset the current string

        # Add the last string if it meets the minimum length
        if len(current_string) >= min_length:
            ascii_strings.append(current_string)

        return ascii_strings
    except Exception as e:
        return f"Error extracting ASCII strings: {e}"

def generate_hex_dump(file_path):
    """Generate a hex dump of a file."""
    try:
        with open(file_path, 'rb') as f:
            hex_dump = ''
            offset = 0
            while chunk := f.read(16):
                hex_part = ' '.join(f"{b:02x}" for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                hex_dump += f"{offset:08x}  {hex_part:<48}  {ascii_part}\n"
                offset += 16
            return hex_dump
    except Exception as e:
        return f"Error generating hex dump: {e}"

def reverse_hex_dump(hex_dump_path, output_path):
    """Reconstruct binary data from a hex dump."""
    try:
        with open(hex_dump_path, 'r') as hex_file, open(output_path, 'wb') as output_file:
            for line in hex_file:
                if len(line) < 10 or not line[:8].strip().isalnum():
                    continue
                hex_data = line[10:58].strip().split()
                binary_data = bytes(int(byte, 16) for byte in hex_data)
                output_file.write(binary_data)
        return f"Binary file reconstructed and saved to {output_path}"
    except Exception as e:
        return f"Error reversing hex dump: {e}"

def calculate_entropy(image_path):
    """
    Calculate the Shannon entropy of an image file.
    """
    try:
        image = Image.open(image_path)
        pixels = np.array(image).flatten()
        histogram, _ = np.histogram(pixels, bins=256, range=(0, 256))
        prob = histogram / np.sum(histogram)
        entropy = -np.sum([p * np.log2(p) for p in prob if p > 0])
        return entropy
    except Exception as e:
        print(f"Error calculating entropy: {e}")
        return None

def analyze_lsb(image_path):
    """
    Analyze the least significant bits (LSBs) of an image for patterns.
    """
    try:
        image = Image.open(image_path)
        if image.mode != 'RGB':
            image = image.convert('RGB')

        pixels = np.array(image)
        if pixels.ndim < 3 or pixels.shape[2] < 3:
            print("Error: Image does not have enough color channels for LSB analysis.")
            return None

        # Extract LSBs for each RGB channel
        lsb_plane = (pixels & 1).reshape(-1, pixels.shape[2])  # Flatten while keeping color channels

        # Count distribution of LSBs per channel
        lsb_distribution = []
        for i in range(3):  # Iterate over Red, Green, Blue channels
            values, counts = np.unique(lsb_plane[:, i], return_counts=True)
            if len(values) < 2:  # Handle cases with fewer than two unique values
                counts = np.append(counts, 0) if values[0] == 0 else np.insert(counts, 0, 0)
                values = np.array([0, 1])  # Ensure both 0 and 1 are present
            lsb_distribution.append((values, counts))
        return lsb_distribution
    except Exception as e:
        print(f"Error analyzing LSB: {e}")
        return None

def extract_lsb(image_path):
    """
    Extract a binary message hidden in the least significant bits (LSBs) of an image.
    """
    try:
        # Open the image
        image = Image.open(image_path)
        if image.mode != 'RGB':
            image = image.convert('RGB')

        # Convert the image into a NumPy array
        pixels = np.array(image)
        
        # Flatten the pixel data
        flat_pixels = pixels.flatten()

        # Extract LSBs from the flattened pixel array
        lsb_bits = ''.join(str(pixel & 1) for pixel in flat_pixels)

        # Group bits into bytes and convert to characters
        message_bytes = bytearray()
        for i in range(0, len(lsb_bits), 8):
            byte_chunk = lsb_bits[i:i+8]
            if len(byte_chunk) == 8:
                byte_value = int(byte_chunk, 2)
                message_bytes.append(byte_value)

        # Detect a null terminator (if used during encoding)
        null_terminator = message_bytes.find(0)
        if null_terminator != -1:
            message_bytes = message_bytes[:null_terminator]

        # Convert to a string if possible
        try:
            message = message_bytes.decode('utf-8')
            print("Extracted Message:")
            print(message)
            return message
        except UnicodeDecodeError:
            print("Warning: Extracted data is not valid UTF-8. Returning raw bytes.")
            return message_bytes
    except Exception as e:
        print(f"Error extracting LSB data: {e}")
        return None

def check_steganography(image_path, extract=False, output_path=None):
    """
    Perform a steganography check by analyzing entropy, LSB patterns, and optionally extracting hidden data.
    """
    if not os.path.exists(image_path):
        print(f"Error: File '{image_path}' does not exist.")
        return

    print(f"Analyzing file: {image_path}\n")

    try:
        # Entropy Analysis
        entropy = calculate_entropy(image_path)
        if entropy:
            print(f"Entropy: {entropy:.4f}")
            if entropy > 7.8:
                print("High entropy detected. File may contain hidden data.")
            else:
                print("Entropy is within normal range.")
        
        # LSB Analysis
        lsb_distribution = analyze_lsb(image_path)
        if lsb_distribution:
            print("\nLSB Distribution (per channel):")
            channels = ['Red', 'Green', 'Blue']
            for channel, dist in zip(channels, lsb_distribution):
                values, counts = dist
                print(f"  {channel} Channel:")
                for value, count in zip(values, counts):
                    print(f"    Bit {value}: {count} pixels")
                if abs(counts[0] - counts[1]) < 0.05 * sum(counts):
                    print(f"    Balanced LSB distribution detected in {channel} channel. Possible steganography.")
                else:
                    print(f"    LSB distribution appears normal in {channel} channel.")

        # LSB Data Extraction
        if extract and output_path:
            extract_lsb(image_path, output_path)
    except Exception as e:
        print(f"Error during steganography check: {e}")

def main():
    parser = argparse.ArgumentParser(description="File Analysis Tool")

    parser.add_argument("-d", "--detect", metavar="FILE", help="Detect the file type.")
    parser.add_argument("-t", "--text", metavar="FILE", help="Extract readable text from a file.")
    parser.add_argument("-x", "--hex", metavar="FILE", help="Generate a hex dump of a file.")
    parser.add_argument("-r", "--reverse", nargs=2, metavar=("HEX_DUMP", "OUTPUT"), help="Reconstruct binary data from a hex dump.")
    parser.add_argument("-s", "--stegcheck", metavar="IMAGE", help="Perform a steganography check on an image file.")
    parser.add_argument("-e", "--stegextract", metavar="IMAGE", help="Extract hidden information from an image.")


    args = parser.parse_args()

    if args.detect:
        result = detect_file_type_with_magic_bytes(args.detect)
        print(f"File Type: {result}")

    if args.text:
        result = extract_ascii_strings(args.text)
        print(f"Readable Text:\n{result}")

    if args.hex:
        result = generate_hex_dump(args.hex)
        print(f"Hex Dump:\n{result}")

    if args.reverse:
        hex_dump_path, output_path = args.reverse
        result = reverse_hex_dump(hex_dump_path, output_path)
        print(result)

    if args.stegcheck:
        check_steganography(args.stegcheck)

    if args.stegextract:
        result = extract_lsb(args.stegextract)
        if isinstance(result, str):
            print(f"Extracted Message:\n{result}")
        elif result:
            print("Raw Bytes Extracted:")
            print(result)
        else:
            print("Failed to extract hidden message.")

if __name__ == "__main__":
    main()

