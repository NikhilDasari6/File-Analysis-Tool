#!/usr/bin/env python3
import argparse
import os
from PIL import Image
import numpy as np
import magic

def detect_file_type(file_path):
    """Detect the type of a file using the magic library."""
    try:
        file_type = magic.from_file(file_path, mime=True)
        return file_type
    except Exception as e:
        return f"Error detecting file type: {e}"

def extract_readable_text(file_path):
    """Extract ASCII and Unicode readable text from a file."""
    readable_text = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            ascii_text = ''.join([chr(b) if 32 <= b < 127 else '.' for b in content])
            readable_text.append("ASCII:\n" + ascii_text)

            try:
                unicode_text = content.decode('utf-8')
                readable_text.append("Unicode:\n" + unicode_text)
            except UnicodeDecodeError:
                readable_text.append("Unicode:\n[Could not decode as UTF-8]")
    except Exception as e:
        return f"Error extracting readable text: {e}"

    return '\n\n'.join(readable_text)

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

def check_steganography(image_path):
    """
    Perform a steganography check by analyzing entropy and LSB patterns.
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
    except Exception as e:
        print(f"Error during steganography check: {e}")

def main():
    parser = argparse.ArgumentParser(description="File Analysis Tool")

    parser.add_argument("-d", "--detect", metavar="FILE", help="Detect the file type.")
    parser.add_argument("-t", "--text", metavar="FILE", help="Extract readable text from a file.")
    parser.add_argument("-x", "--hex", metavar="FILE", help="Generate a hex dump of a file.")
    parser.add_argument("-r", "--reverse", nargs=2, metavar=("HEX_DUMP", "OUTPUT"), help="Reconstruct binary data from a hex dump.")
    parser.add_argument("-s", "--stegcheck", metavar="IMAGE", help="Perform a steganography check on an image file.")

    args = parser.parse_args()

    if args.detect:
        result = detect_file_type(args.detect)
        print(f"File Type: {result}")

    if args.text:
        result = extract_readable_text(args.text)
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

if __name__ == "__main__":
    main()

