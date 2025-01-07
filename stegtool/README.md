# README.md

## StegTool: File Analysis and Steganography Utility

### Overview
StegTool is a powerful and versatile command-line utility designed for file analysis and steganography tasks. It provides various methods for encoding and decoding hidden data, analyzing files, and performing steganography checks. This tool is ideal for professionals, researchers, and enthusiasts working in digital forensics, cybersecurity, or data privacy.

---

### Features

1. **File Type Detection**
   - Detects file types using magic bytes.

2. **Text Extraction**
   - Extracts readable ASCII strings from any binary file.

3. **Hex Dump Generation**
   - Generates a hex dump of the specified file.

4. **Hex Dump Reconstruction**
   - Reconstructs binary files from hex dumps.

5. **Steganography Check**
   - Analyzes image entropy and LSB (Least Significant Bit) patterns to detect potential hidden data.

6. **LSB Data Extraction**
   - Extracts ASCII-readable bytes from the LSBs of images.

7. **Text Encoding Using LSB**
   - Hides a secret message in an image by manipulating its LSBs based on a user-defined key.

8. **Text Decoding from LSB**
   - Retrieves hidden messages from images using the LSB method and a user-defined key.

---

### Methods of Steganography Encoding

1. **Least Significant Bit (LSB) Encoding**
   - Uses the least significant bits of pixel values to encode the binary representation of the hidden message.
   - A non-linear, key-based pattern ensures enhanced security and reduces detectability.

2. **Entropy-Based Analysis**
   - Computes Shannon entropy to detect anomalies in image data, which might indicate the presence of hidden information.

3. **Key-Based Pixel Selection**
   - A user-defined key generates a pseudo-random sequence of pixel indices for message embedding, ensuring the encoded data is difficult to detect.

---

### Usage

```bash
stegtool [OPTIONS]
```

#### Options

- `-d, --detect FILE`
  Detect the file type using magic bytes.

- `-t, --text FILE`
  Extract readable ASCII strings from a file.

- `-x, --hex FILE`
  Generate a hex dump of a file.

- `-r, --reverse HEX_DUMP OUTPUT`
  Reconstruct binary data from a hex dump.

- `-s, --stegcheck IMAGE`
  Perform a steganography check on an image file.

- `-e, --stegextract IMAGE`
  Extract hidden information from an image.

- `--encode IMAGE ENCODED_IMAGE`
  Encode hidden text in an image.

- `--decode ENCODED_IMAGE`
  Decode hidden text from an image.

---

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/NikhilDasari6/File-Analysis-Tool
   cd stegtool
   ```

2. Install the package:
   ```bash
   python3 setup.py install
   ```

3. Run the tool:
   ```bash
   stegtool --help
   ```

---

### License
StegTool is licensed under the MIT License. See the `LICENSE` file for details.

---

### Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your enhancements.

---

### Acknowledgments
This tool leverages powerful libraries like Pillow and NumPy for image processing and analysis.


