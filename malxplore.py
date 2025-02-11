import hashlib
import os
import magic
import yara
import math
import string
import whois
import json
import datetime
import re
import pefile
import argparse
import requests
from collections import Counter
from PIL import Image, ExifTags
from concurrent.futures import ThreadPoolExecutor

VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your API key

def read_file(file_path):
    """Read file content in binary mode."""
    try:
        with open(file_path, "rb") as f:
            return f.read(), None  # Return the data and None for no error
    except Exception as e:
        return None, str(e)  # Return None for data and the error message

def calculate_hashes(data):
    """Compute file hashes (SHA-256, MD5, SHA-1) using threading."""
    def compute_hash(algo):
        hasher = hashlib.new(algo)
        hasher.update(data)
        return hasher.hexdigest()

    if data is None:
        return {"Error": "Failed to read file"}

    hash_algos = ["sha256", "md5", "sha1"]
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(compute_hash, hash_algos))
    
    return dict(zip(["SHA-256", "MD5", "SHA-1"], results))

def extract_metadata(file_path):
    """Extract file metadata."""
    try:
        stat = os.stat(file_path)
        return {
            "File Size": stat.st_size,
            "Creation Time": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "Modification Time": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "Permissions": oct(stat.st_mode)
        }
    except Exception as e:
        return {"Error": str(e)}

def detect_network_indicators(data):
    """Detect embedded IPs and URLs."""
    if data is None:
        return {"Error": "Failed to read file"}
    
    decoded_data = data.decode(errors='ignore')
    ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', decoded_data)))
    urls = list(set(re.findall(r'https?://[\w./-]+', decoded_data)))
    
    whois_results = {}
    for url in urls[:5]:  # Limit WHOIS lookups
        try:
            domain = re.findall(r'https?://([^/]+)', url)[0]
            whois_results[domain] = whois.whois(domain)
        except Exception:
            whois_results[domain] = "WHOIS lookup failed"

    return {"IPs": ips, "URLs": urls, "WHOIS": whois_results}

def analyze_pe(file_path):
    """Extract PE file details."""
    try:
        pe = pefile.PE(file_path)
        return {
            "Entry Point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "Image Base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "Sections": [section.Name.decode().strip() for section in pe.sections],
            "Imported DLLs": [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]
        }
    except Exception as e:
        return {"Error": str(e)}

def detect_file_type(file_path):
    """Detect file type using libmagic."""
    try:
        return magic.from_file(file_path)
    except Exception as e:
        return {"Error": str(e)}

def calculate_entropy(data):
    """Calculate Shannon entropy."""
    if data is None:
        return {"Error": "Failed to read file"}
    
    counts = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values() if count)
    return entropy

def extract_strings(data, min_length=4):
    """Extract readable strings from binary data using threading."""
    if data is None:
        return {"Error": "Failed to read file"}

    printable = string.printable.encode()
    result = "".join(chr(c) if c in printable else " " for c in data)
    words = [word for word in result.split() if len(word) >= min_length]
    
    return words[:100]  # Limit output

def yara_scan(file_path, rule_path="malware_rules.yara"):
    """Scan file using YARA."""
    try:
        rules = yara.compile(filepath=rule_path)
        matches = rules.match(file_path)
        return [match.rule for match in matches] if matches else ["No YARA matches found."]
    except Exception as e:
        return {"Error": str(e)}

def extract_exif(file_path):
    """Extract EXIF metadata from images."""
    try:
        image = Image.open(file_path)
        exif_data = {ExifTags.TAGS.get(tag, tag): value for tag, value in image._getexif().items()} if image._getexif() else {}
        return exif_data
    except Exception as e:
        return {"Error": str(e)}

def check_virustotal(file_path):
    """Check file hash against VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return {"Error": "VirusTotal API key is missing"}

    data, _ = read_file(file_path)
    if data is None:
        return {"Error": "Failed to read file"}
    
    file_hash = hashlib.sha256(data).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"Error": f"VirusTotal lookup failed: {response.status_code}"}

def save_output(filename, data):
    """Save JSON output to a file."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving output: {e}")

def main():
    parser = argparse.ArgumentParser(description="Advanced File Analysis Tool")
    parser.add_argument("file_path", help="Path to the file to analyze")
    parser.add_argument("--virustotal", action="store_true", help="Check file against VirusTotal")
    args = parser.parse_args()

    file_path = args.file_path
    if not os.path.exists(file_path):
        print("File not found!")
        return

    data, error = read_file(file_path)
    if error:
        print(f"Error reading file: {error}")
        return

    output = {
        "Metadata": extract_metadata(file_path),
        "Hashes": calculate_hashes(data),
        "File Type": detect_file_type(file_path),
        "Entropy": calculate_entropy(data),
        "Extracted Strings": extract_strings(data),
        "Network Indicators": detect_network_indicators(data),
        "PE Analysis": analyze_pe(file_path),
        "YARA Scan": yara_scan(file_path),
        "EXIF Data": extract_exif(file_path)
    }

    if args.virustotal:
        output["VirusTotal"] = check_virustotal(file_path)

    save_output("analysis_report.json", output)
    print("Analysis complete. Report saved to analysis_report.json")

if __name__ == "__main__":
    main()
