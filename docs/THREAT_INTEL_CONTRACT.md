# Threat Intel Bin Contract Specification

**Version:** 1.0  
**Last Updated:** 2026-04-19  
**Purpose:** Defines the binary format for threat intelligence data consumed by GuardLens

## Overview

This specification defines the binary format, encoding, encryption, and validation mechanisms for threat intelligence data published by emergentek-threat-lab and consumed by GuardLens.

## File Naming Convention

```
threat-intel-v{VERSION}-{YYYYMMDD}-{TIMESTAMP}.bin
threat-intel-v{VERSION}-{YYYYMMDD}-{TIMESTAMP}.sha256
```

Example:
```
threat-intel-v1.0-20240419-142530.bin
threat-intel-v1.0-20240419-142530.sha256
```

## Binary Format Structure

### Header (Fixed: 64 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Magic Number | `0x474C5449` (ASCII: "GLTI") |
| 4 | 2 | Version | Major.Minor (e.g., 0x01 0x00 = v1.0) |
| 6 | 4 | Format Version | Binary format version |
| 10 | 8 | Timestamp | Unix timestamp (UTC) |
| 18 | 4 | Entry Count | Number of threat entries |
| 22 | 2 | Compression Type | 0=none, 1=gzip, 2=zlib |
| 24 | 2 | Encryption Type | 0=none, 1=AES-256-GCM |
| 26 | 38 | Reserved | Future use, must be zeros |

### Payload (Variable Size)

#### If Unencrypted & Uncompressed:

```
[Entry Count] × [Threat Entry]
```

#### If Encrypted:

```
[12 bytes] Nonce (for AES-GCM)
[16 bytes] Authentication Tag
[Encrypted Data]
```

#### If Compressed:

```
[Compressed Entry Data]
```

## Threat Entry Format

Each threat entry (unencrypted, uncompressed):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Hash Length | Length of hash field |
| 4 | N | Hash | SHA-256 hash (32 bytes typical) |
| 4+N | 2 | Threat Type | 0=domain, 1=ip, 2=url, 3=file_hash |
| 6+N | 2 | Severity | 0=info, 1=low, 2=medium, 3=high, 4=critical |
| 8+N | 2 | Category Length | Length of category string |
| 10+N | M | Category | Category string (UTF-8) |
| 10+N+M | 2 | Source Length | Length of source string |
| 12+N+M | K | Source | Source identifier (UTF-8) |
| 12+N+M+K | 4 | First Seen | Unix timestamp |
| 16+N+M+K | 4 | Last Seen | Unix timestamp |
| 20+N+M+K | 2 | Confidence | 0-100 confidence score |
| 22+N+M+K | 2 | Reserved | Future use, must be zero |

## Checksum Format

The `.sha256` file contains the SHA-256 hash of the `.bin` file in hexadecimal format:

```
<SHA256_HASH>  <FILENAME>
```

Example:
```
a1b2c3d4e5f6...  threat-intel-v1.0-20240419-142530.bin
```

## Download URL Structure

```
https://threat-intel.emergentek.com/v1.0/threat-intel-v{VERSION}-{YYYYMMDD}-{TIMESTAMP}.bin
https://threat-intel.emergentek.com/v1.0/threat-intel-v{VERSION}-{YYYYMMDD}-{TIMESTAMP}.sha256
```

## Encryption Specification

When encryption is enabled (Encryption Type = 1):

- **Algorithm:** AES-256-GCM
- **Key Derivation:** PBKDF2 with HMAC-SHA256
- **Iterations:** 100,000
- **Salt:** Included in header (first 16 bytes of payload)
- **Nonce:** 12 bytes (included after header)
- **Tag:** 16 bytes (included after nonce)

## Compression Specification

When compression is enabled:

- **Type 1 (gzip):** Standard gzip compression
- **Type 2 (zlib):** Standard zlib compression
- Compression applied before encryption if both enabled

## Validation Rules

### Consumer (GuardLens) Must Verify:

1. **Magic Number:** Must be `0x474C5449`
2. **Version Compatibility:** Must support specified version
3. **Checksum:** SHA-256 must match `.sha256` file
4. **Timestamp:** Must be within acceptable age (configurable, default 7 days)
5. **Entry Count:** Must match actual entries in payload

### Producer (emergentek-threat-lab) Must Ensure:

1. **Valid Structure:** All fields present and correctly sized
2. **Consistent Encoding:** UTF-8 for all string fields
3. **Proper Encryption:** Valid nonce, tag, and key derivation
4. **Accurate Checksum:** SHA-256 matches binary file
5. **Version Compatibility:** Backward compatible with supported versions

## Error Handling

### Invalid Magic Number:
- Action: Reject bin, log error
- Retry: Download from backup URL

### Checksum Mismatch:
- Action: Reject bin, log security alert
- Retry: Download from backup URL

### Version Incompatibility:
- Action: Use cached bin if available
- Fallback: Graceful degradation with warning

### Timestamp Too Old:
- Action: Warn user, attempt refresh
- Fallback: Use cached bin with warning

## Security Considerations

1. **HTTPS Only:** All downloads must use HTTPS
2. **Certificate Pinning:** Consider pinning threat-intel.emergentek.com certificate
3. **Signature Verification:** Future: Add Ed25519 signature support
4. **Key Management:** Encryption keys should be derived from app secret, not hardcoded
5. **Cache Security:** Encrypted bins should be stored securely
6. **Tamper Detection:** Any modification should be detected and rejected

## Future Extensions

Reserved fields in header and entries allow for future expansion:
- Additional metadata fields
- New threat types
- Signature verification
- Incremental updates (delta patches)

## Example Implementation Flow

```
1. Download .sha256 file
2. Download .bin file
3. Verify SHA-256 checksum
4. Read and validate header
5. Check version compatibility
6. Check timestamp age
7. If encrypted: derive key, decrypt payload
8. If compressed: decompress
9. Parse entries into hash map
10. Cache locally with timestamp
11. Use for threat detection
```
