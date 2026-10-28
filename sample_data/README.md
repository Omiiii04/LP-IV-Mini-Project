# Sample & Test Data (Synthetic Only)

> **ACADEMIC & TESTING DISCLAIMER**
> All files in this directory are **100% synthetic**. All IP addresses (using RFC 5737 documentation prefixes such as `198.51.100.0/24` and `203.0.113.0/24` or private RFC 1918 addresses), usernames, system hostnames, log entries, and disk images are generated purely for forensic training, unit testing, and demonstration.
> **DO NOT** commit real, proprietary, or private evidentiary materials to this repository.

## Files Overview

| File | Type | Description / Forensic Relevance |
| :--- | :--- | :--- |
| `auth.log` | Linux Syslog | SSH brute-force attempts from two distinct IPs (`192.168.1.105` and `203.0.113.45`), followed by a successful login and privilege escalation lead. |
| `nginx_access.log` | Nginx Access Log | Web server traffic containing directory traversal probes (`/etc/passwd`, `win.ini`) and SQL injection attempts (`' OR '1'='1`, `UNION SELECT`). |
| `windows_security.csv` | Windows Security Log | Structured CSV containing Windows Event IDs `4625` (failed logon attempts) and `4624` (successful logon). |
| `clean_baseline.log` | System Log | Benign baseline system log generated during standard business hours that produces **zero** flagged security patterns. |
| `notes.txt` | Text Document | Forensic triage notes, chain-of-custody transfer records, and evidence preservation ledger. |
| `small.pdf` | Document (PDF) | Lightweight, valid PDF document for document preview and file analysis tests. |
| `mbr_fat.img` | Disk Image (128 KB) | Synthetic Master Boot Record (MBR) disk image with a FAT32 partition. Built deterministically via `scripts/make_sample_images.py`. |
| `gpt_ext4.img` | Disk Image (128 KB) | Synthetic GUID Partition Table (GPT) disk image with a Linux native filesystem partition. |
| `raw_unpartitioned.dd` | Disk Dump (64 KB) | Raw physical bitstream image without partition tables. |
| `corrupt_header.img` | Disk Image (64 KB) | Truncated/damaged GPT header to verify structured warnings parsing without unhandled crashes. |

## Generating Disk Images

To deterministically re-generate the sample disk images at any time:

```bash
python scripts/make_sample_images.py
```
