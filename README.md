# Emergentek Threat Lab

Automated threat intelligence feed aggregation and distribution system for GuardLens and compatible security tools.

## Overview

This repository contains scripts and workflows to aggregate threat intelligence from multiple sources and distribute them in a standardized binary format compatible with the [Threat Intel Bin Contract Specification](docs/THREAT_INTEL_CONTRACT.md).

## Features

- **Automated Daily Updates**: GitHub Actions workflow runs daily to fetch and aggregate threat data
- **Multiple Data Sources**: Aggregates from OpenPhish, URLhaus, and StevenBlack/hosts
- **Standardized Binary Format**: Compliant with v1.0 of the Threat Intel Bin Contract
- **Versioned Releases**: Both "latest" and versioned releases for traceability
- **SHA256 Checksums**: All binary files include SHA256 checksums for integrity verification

## Binary Format

The generated binary files follow the contract specification defined in [docs/THREAT_INTEL_CONTRACT.md](docs/THREAT_INTEL_CONTRACT.md). Key features:

- **64-byte header** with magic number, version, timestamp, and metadata
- **Compressed payload** using zlib for efficient storage
- **Structured threat entries** with hash, type, severity, category, source, and confidence
- **SHA256 verification** for integrity checking

## File Naming Convention

```
threat-intel-v{VERSION}-{YYYYMMDD}-{TIMESTAMP}.bin
threat-intel-v{VERSION}-{YYYYMMDD}-{TIMESTAMP}.sha256
latest.json
```

Example:
```
threat-intel-v1.0-20260419-142530.bin
threat-intel-v1.0-20260419-142530.sha256
```

## Consumer Integration

Consumers (like GuardLens) can integrate with this feed by:

1. **Fetching latest.json** to get the current binary file URL:
   ```json
   {
     "version": "1.0",
     "timestamp": 1713530730,
     "bin_url": "https://github.com/emergentek-max/emergentek-threat-lab/releases/download/latest/threat-intel-v1.0-20260419-142530.bin",
     "sha256_url": "https://github.com/emergentek-max/emergentek-threat-lab/releases/download/latest/threat-intel-v1.0-20260419-142530.sha256",
     "entry_count": 150000
   }
   ```

2. **Downloading and verifying** the binary file using the SHA256 checksum

3. **Parsing the binary** according to the contract specification

See the [contract documentation](docs/THREAT_INTEL_CONTRACT.md) for detailed implementation guidance.

## Data Sources

Current threat intelligence sources:
- **OpenPhish**: Phishing feed
- **URLhaus**: Malware URL feed
- **StevenBlack/hosts**: Adware and malware hosts

## Local Development

### Requirements

- Python 3.11+
- requests library

### Running the Aggregator

```bash
pip install requests
python aggregator.py
```

This will generate:
- `threat-intel-v1.0-{DATE}-{TIME}.bin` - Binary threat intelligence file
- `threat-intel-v1.0-{DATE}-{TIME}.sha256` - SHA256 checksum
- `latest.json` - Metadata file with download URLs

## GitHub Actions

The repository includes a GitHub Actions workflow (`.github/workflows/daily_sync.yml`) that:

1. Runs daily at midnight UTC
2. Executes the aggregator script
3. Creates/updates the "latest" release with current files
4. Creates a versioned release (v1.0-{build_number}) for historical tracking

The workflow can also be triggered manually via `workflow_dispatch`.

## License

Copyright 2026 Emergentek LLC

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Security Considerations

- All downloads should use HTTPS
- Verify SHA256 checksums before using binary files
- Check timestamps to ensure data freshness (recommended max age: 7 days)
- Implement proper error handling for network failures

## Support

For questions about the binary format or integration, refer to the [contract specification](docs/THREAT_INTEL_CONTRACT.md).
