# MalXplore: Advanced File Analysis Tool

MalXplore is a powerful tool designed for performing detailed file analysis. It provides various functionalities to analyze files for their metadata, hashes, potential embedded network indicators, file type, entropy, strings, PE file details, and even integrates with VirusTotal to check files for potential threats. This tool supports multi-threaded file operations to improve performance on large files.

## Features

- **File Metadata Extraction**: Extracts file size, creation and modification timestamps, and permissions.
- **Hash Calculation**: Computes file hashes (SHA-256, MD5, SHA-1) using multi-threading for improved performance.
- **File Type Detection**: Uses `libmagic` to determine the file type.
- **Entropy Calculation**: Measures file entropy to detect unusual or potentially obfuscated files.
- **String Extraction**: Extracts readable strings from binary data with a configurable minimum string length.
- **Network Indicators Detection**: Identifies embedded IP addresses and URLs, and performs WHOIS lookups on detected URLs.
- **PE File Analysis**: Extracts key details from PE (Portable Executable) files such as entry points, image base, sections, and imported DLLs.
- **YARA Scan**: Runs a YARA rule scan against the file to detect potential threats.
- **EXIF Metadata Extraction**: Extracts EXIF data from image files.
- **VirusTotal Integration**: Checks file hashes against VirusTotal for virus and malware detection.
- **Multi-threaded Operations**: Uses `ThreadPoolExecutor` for parallel processing to improve speed.

## Requirements

To run this tool, you'll need to install the dependencies listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Required Python Libraries:
- hashlib
- os
- magic
- yara
- math
- string
- whois
- json
- datetime
- re
- pefile
- argparse
- requests
- collections
- PIL
- concurrent.futures

## Setup
1- VirusTotal API Key: You'll need to sign up at VirusTotal and get your API key. Replace the placeholder YOUR_VIRUSTOTAL_API_KEY with your actual API key in the script.
2- Install Dependencies: Install the required libraries using pip:
```bash
pip install -r requirements.txt
```

## Usage
To run the analysis on a file, use the following command:

```bash
python malxplore.py /path/to/your/file
```

To include a VirusTotal scan, use the --virustotal flag:

```bash
python malxplore.py /path/to/your/file --virustotal
```



