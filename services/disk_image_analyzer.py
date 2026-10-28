import struct
import uuid
from pathlib import Path

from .hashing import multi_hash_file

MBR_PARTITION_TYPES = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 (<32MB)",
    0x05: "Extended Partition",
    0x06: "FAT16",
    0x07: "NTFS / exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended Partition (LBA)",
    0x82: "Linux Swap",
    0x83: "Linux Native (ext2/3/4)",
    0x8E: "Linux LVM",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System Partition",
}

GPT_PARTITION_GUIDS = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System Partition",
    "024DEE41-33E7-11D3-9D69-0008C781F39F": "MBR Partition Scheme",
    "21686148-6449-6E6F-744E-656564454649": "BIOS Boot Partition",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Microsoft LD-Metadata",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "Microsoft LD-Data",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery Environment",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux Filesystem Data",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux Swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD UFS",
}


def _format_size(num_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def _bytes_to_guid_str(guid_bytes: bytes) -> str:
    """Formats GUID according to mixed-endian UEFI specification."""
    if len(guid_bytes) != 16:
        return ""
    try:
        return str(uuid.UUID(bytes_le=guid_bytes)).upper()
    except Exception:
        return ""


def _parse_mbr(data: bytes, sector_size: int = 512) -> tuple[list[dict] | None, list[str]]:
    """Parses MBR partition table from boot sector if 0x55AA signature is valid."""
    warnings = []
    if len(data) < 512:
        return None, ["Data too short for MBR boot sector"]
    if data[510:512] != b"\x55\xaa":
        return None, []

    partitions = []
    # 4 partition entries of 16 bytes starting at offset 446
    for i in range(4):
        offset = 446 + (i * 16)
        entry = data[offset : offset + 16]
        boot_flag, _, _, _, part_type, _, _, _, start_lba, num_sectors = struct.unpack("<BBBBBBBBII", entry)

        if part_type == 0x00 and num_sectors == 0:
            continue

        size_bytes = num_sectors * sector_size
        partitions.append(
            {
                "slot": i + 1,
                "bootable": boot_flag == 0x80,
                "type_id": f"0x{part_type:02X}",
                "type_name": MBR_PARTITION_TYPES.get(part_type, f"Unknown (0x{part_type:02X})"),
                "start_lba": start_lba,
                "num_sectors": num_sectors,
                "size_bytes": size_bytes,
                "size_formatted": _format_size(size_bytes),
            }
        )

    return partitions, warnings


def _parse_gpt(data: bytes, sector_size: int = 512) -> tuple[list[dict] | None, list[str]]:
    """Parses GPT partition header and entries, honoring sector size and capturing warnings."""
    warnings = []
    if len(data) < sector_size * 2:
        return None, []

    header = data[sector_size : sector_size + 92]
    if len(header) < 92 or header[:8] != b"EFI PART":
        return None, []

    try:
        # Full 92-byte GPT header according to UEFI spec:
        # 8s (Signature: "EFI PART")
        # I  (Revision)
        # I  (Header Size)
        # I  (Header CRC32)
        # I  (Reserved)
        # Q  (Current LBA)
        # Q  (Backup LBA)
        # Q  (First Usable LBA)
        # Q  (Last Usable LBA)
        # 16s(Disk GUID)
        # Q  (Partition Entry LBA)
        # I  (Number of Partition Entries)
        # I  (Size of Partition Entry)
        # I  (Partition Array CRC32)
        (
            sig,
            rev,
            hdr_size,
            hdr_crc,
            reserved,
            curr_lba,
            backup_lba,
            first_usable_lba,
            last_usable_lba,
            disk_guid,
            part_entry_lba,
            num_entries,
            entry_size,
            part_crc,
        ) = struct.unpack("<8sIIIIQQQQ16sQIII", header[:92])

        if hdr_size < 92:
            warnings.append(f"Unusual GPT header size reported: {hdr_size} bytes")

        entries_offset = part_entry_lba * sector_size
        partitions = []
        needed_bytes = entries_offset + (num_entries * entry_size)

        if len(data) < needed_bytes:
            warnings.append(
                f"GPT partition table truncated: requires {needed_bytes} bytes, file header buffer has {len(data)} bytes"
            )

        # Inspect up to max available entries or 128
        max_scan = min(num_entries, 128)
        for i in range(max_scan):
            e_off = entries_offset + (i * entry_size)
            if e_off + entry_size > len(data):
                break
            e_data = data[e_off : e_off + entry_size]
            if len(e_data) < 128:
                continue

            type_guid_raw = e_data[:16]
            if type_guid_raw == b"\x00" * 16:
                continue  # unused partition entry

            type_guid_str = _bytes_to_guid_str(type_guid_raw)
            type_name = GPT_PARTITION_GUIDS.get(type_guid_str, f"Unknown ({type_guid_str})")

            unique_guid_str = _bytes_to_guid_str(e_data[16:32])
            start_lba, end_lba, flags = struct.unpack("<QQQ", e_data[32:56])
            name_raw = e_data[56:128]
            name = name_raw.decode("utf-16le", errors="replace").split("\x00")[0].strip()

            num_sectors = max(0, (end_lba - start_lba) + 1)
            size_bytes = num_sectors * sector_size

            partitions.append(
                {
                    "slot": i + 1,
                    "name": name or f"Partition {i + 1}",
                    "type_guid": type_guid_str,
                    "type_name": type_name,
                    "unique_guid": unique_guid_str,
                    "start_lba": start_lba,
                    "end_lba": end_lba,
                    "flags": flags,
                    "num_sectors": num_sectors,
                    "size_bytes": size_bytes,
                    "size_formatted": _format_size(size_bytes),
                }
            )

        return partitions, warnings
    except Exception as exc:
        warnings.append(f"GPT parsing error: {exc}")
        return [], warnings


def _detect_filesystem_signatures(data: bytes) -> list[str]:
    """Inspects common filesystem boot headers."""
    fs_list = []
    if len(data) >= 512:
        if b"NTFS    " in data[:512]:
            fs_list.append("NTFS")
        if b"FAT32   " in data[:512] or b"FAT16   " in data[:512] or b"FAT12   " in data[:512]:
            fs_list.append("FAT")
        if len(data) >= 2048 and data[1080:1082] == b"\x53\xef":
            fs_list.append("ext2/3/4")
    return fs_list


def examine(path: str | Path) -> dict:
    """
    Examines disk image (.dd / .img), computes multi-hashes, and extracts partition geometry.
    Supports both 512-byte and 4096-byte sectors. Returns structured warnings.
    """
    path = Path(path)
    if path.suffix.lower() not in {".dd", ".img"}:
        raise ValueError("unsupported disk-image format; use .dd or .img")

    size = path.stat().st_size
    hashes = multi_hash_file(path)
    sha256 = hashes["sha256"]
    warnings: list[str] = []

    # Read up to 256KB for partition tables (accommodates 4096 sector GPT structures)
    read_len = min(size, 262144)
    with path.open("rb") as stream:
        header_data = stream.read(read_len)

    # First attempt GPT with 512 sector size, then 4096 sector size
    gpt_parts, gpt_warns = _parse_gpt(header_data, sector_size=512)
    detected_sector_size = 512
    if gpt_parts is None or len(gpt_parts) == 0:
        gpt_4k, gpt_4k_warns = _parse_gpt(header_data, sector_size=4096)
        if gpt_4k is not None and len(gpt_4k) > 0:
            gpt_parts = gpt_4k
            detected_sector_size = 4096
            warnings.extend(gpt_4k_warns)
        elif gpt_warns:
            warnings.extend(gpt_warns)
    else:
        warnings.extend(gpt_warns)

    mbr_parts, mbr_warns = _parse_mbr(header_data, sector_size=detected_sector_size)
    warnings.extend(mbr_warns)

    detected_fs = _detect_filesystem_signatures(header_data)

    scheme = "Raw / Non-partitioned"
    partitions = []

    if gpt_parts is not None and len(gpt_parts) > 0:
        scheme = "GPT (GUID Partition Table)"
        partitions = gpt_parts
    elif mbr_parts is not None and len(mbr_parts) > 0:
        if any(p.get("type_id") == "0xEE" for p in mbr_parts):
            scheme = "GPT (Protective MBR)"
        else:
            scheme = "MBR (Master Boot Record)"
        partitions = mbr_parts

    message = (
        f"Native {scheme} inspection completed ({len(partitions)} partition(s) identified, "
        f"{detected_sector_size}-byte sectors). Cryptographic baseline recorded."
    )

    return {
        "path": path.name,
        "sha256_before": sha256,
        "sha256": sha256,
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "size": size,
        "size_formatted": _format_size(size),
        "sector_size": detected_sector_size,
        "read_only": True,
        "scheme": scheme,
        "partitions": partitions,
        "detected_filesystems": detected_fs,
        "warnings": warnings,
        "message": message,
    }
