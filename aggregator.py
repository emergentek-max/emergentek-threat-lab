import requests
import hashlib
import struct
import zlib
import time
from datetime import datetime
from urllib.parse import urlparse
import json

SOURCES = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]

CONTRACT_VERSION = "1.0"
FORMAT_VERSION = 1
MAGIC_NUMBER = 0x474C5449  # "GLTI" in ASCII

THREAT_TYPE_DOMAIN = 0
THREAT_TYPE_IP = 1
THREAT_TYPE_URL = 2

SEVERITY_INFO = 0
SEVERITY_LOW = 1
SEVERITY_MEDIUM = 2
SEVERITY_HIGH = 3
SEVERITY_CRITICAL = 4


def parse_source(text, source_name):
    """Parse threat intelligence from various source formats."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue

        parts = line.split()
        threat_value = None
        threat_type = THREAT_TYPE_DOMAIN

        if len(parts) > 1 and parts[0] in ["0.0.0.0", "127.0.0.1"]:
            threat_value = parts[1].lower()
            threat_type = THREAT_TYPE_DOMAIN
        else:
            threat_value = line.lower()
            if "/" in threat_value:
                threat_type = THREAT_TYPE_URL
            elif threat_value.replace(".", "").isdigit():
                threat_type = THREAT_TYPE_IP
            else:
                threat_type = THREAT_TYPE_DOMAIN

        if threat_value:
            entry = {
                "hash": hashlib.sha256(threat_value.encode("utf-8")).digest(),
                "threat_type": threat_type,
                "severity": SEVERITY_HIGH,
                "category": "malware",
                "source": source_name,
                "first_seen": int(time.time()),
                "last_seen": int(time.time()),
                "confidence": 85,
            }
            entries.append(entry)

    return entries


def create_threat_entry(entry):
    """Serialize a single threat entry according to the contract."""
    data = bytearray()

    hash_bytes = entry["hash"]
    data.extend(len(hash_bytes).to_bytes(4, "big"))
    data.extend(hash_bytes)

    data.extend(entry["threat_type"].to_bytes(2, "big"))
    data.extend(entry["severity"].to_bytes(2, "big"))

    category_bytes = entry["category"].encode("utf-8")
    data.extend(len(category_bytes).to_bytes(2, "big"))
    data.extend(category_bytes)

    source_bytes = entry["source"].encode("utf-8")
    data.extend(len(source_bytes).to_bytes(2, "big"))
    data.extend(source_bytes)

    data.extend(entry["first_seen"].to_bytes(4, "big"))

    data.extend(entry["last_seen"].to_bytes(4, "big"))

    data.extend(entry["confidence"].to_bytes(2, "big"))

    data.extend((0).to_bytes(2, "big"))

    return bytes(data)


def create_header(entry_count, timestamp):
    """Create the 64-byte header according to the contract."""
    header = bytearray(64)

    header[0:4] = MAGIC_NUMBER.to_bytes(4, "big")

    version_parts = CONTRACT_VERSION.split(".")
    header[4:6] = (int(version_parts[0]) << 8 | int(version_parts[1])).to_bytes(
        2, "big"
    )

    header[6:10] = FORMAT_VERSION.to_bytes(4, "big")

    header[10:18] = timestamp.to_bytes(8, "big")

    header[18:22] = entry_count.to_bytes(4, "big")

    header[22:24] = (2).to_bytes(2, "big")

    header[24:26] = (0).to_bytes(2, "big")

    header[26:64] = bytes(38)

    return bytes(header)


def run():
    """Main execution function."""
    all_entries = []
    timestamp = int(time.time())

    print("Fetching feeds...")
    for url in SOURCES:
        source_name = urlparse(url).netloc
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                entries = parse_source(r.text, source_name)
                all_entries.extend(entries)
                print(f"Fetched {len(entries)} entries from {source_name}")
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")

    unique_entries = {}
    for entry in all_entries:
        hash_hex = entry["hash"].hex()
        if hash_hex not in unique_entries:
            unique_entries[hash_hex] = entry

    unique_entries = list(unique_entries.values())
    print(f"Total unique entries: {len(unique_entries)}")

    payload_data = bytearray()
    for entry in unique_entries:
        payload_data.extend(create_threat_entry(entry))

    compressed_payload = zlib.compress(bytes(payload_data))
    print(
        f"Compressed payload size: {len(compressed_payload)} bytes (uncompressed: {len(payload_data)} bytes)"
    )

    header = create_header(len(unique_entries), timestamp)

    binary_data = header + compressed_payload
    date_str = datetime.utcfromtimestamp(timestamp).strftime("%Y%m%d")
    time_str = datetime.utcfromtimestamp(timestamp).strftime("%H%M%S")
    bin_filename = f"threat-intel-v{CONTRACT_VERSION}-{date_str}-{time_str}.bin"

    with open(bin_filename, "wb") as f:
        f.write(binary_data)

    sha256_hash = hashlib.sha256(binary_data).hexdigest()
    sha256_filename = bin_filename.replace(".bin", ".sha256")
    with open(sha256_filename, "w") as f:
        f.write(f"{sha256_hash}  {bin_filename}\n")

    latest_json = {
        "version": CONTRACT_VERSION,
        "timestamp": timestamp,
        "bin_url": f"https://www.emergentekslabs.com/api/guardlens/v1.0/{bin_filename}",
        "sha256_url": f"https://www.emergentekslabs.com/api/guardlens/v1.0/{sha256_filename}",
        "entry_count": len(unique_entries),
    }

    with open("latest.json", "w") as f:
        json.dump(latest_json, f, indent=2)

    print(f"Success: Generated {bin_filename}, {sha256_filename}, and latest.json")
    print(f"SHA256: {sha256_hash}")

    return bin_filename, sha256_filename


if __name__ == "__main__":
    run()
