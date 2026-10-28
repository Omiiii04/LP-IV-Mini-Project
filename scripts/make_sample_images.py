#!/usr/bin/env python3
"""Deterministic generator for synthetic sample forensic disk images.

Generates tiny, deterministic images in sample_data/ for automated testing and training:
- mbr_fat.img: MBR partition scheme with a FAT32 partition (128 KB)
- gpt_ext4.img: UEFI GPT partition scheme with a Linux filesystem partition (128 KB)
- raw_unpartitioned.dd: Raw dd bitstream dump without partition structures (64 KB)
- corrupt_header.img: Damaged GPT header testing structured warning parser (64 KB)
"""

import struct
import uuid
import zlib
from pathlib import Path


def generate_mbr_fat(out_path: Path, size_kb: int = 128) -> None:
    """Generates a synthetic MBR disk image containing a FAT32 partition entry."""
    total_bytes = size_kb * 1024
    image = bytearray(total_bytes)

    # Boot code message
    msg = b"DFT SYNTHETIC MBR TEST IMAGE -- NOT A REAL DISK"
    image[0 : len(msg)] = msg

    # MBR Boot Signature at offset 510-511
    image[510:512] = b"\x55\xaa"

    # Partition Entry 1 at offset 446 (16 bytes):
    # struct format: <BBBBBBBBII
    # Bootable (0x80), CHS start (0,1,1), Type 0x0B (FAT32 CHS), CHS end (0,1,1), Start LBA 32, Sectors 200
    part_entry = struct.pack(
        "<BBBBBBBBII",
        0x80,  # Bootable
        0x00,
        0x01,
        0x01,  # CHS start
        0x0B,  # Type: FAT32 (CHS)
        0x00,
        0x01,
        0x01,  # CHS end
        32,  # Start LBA
        200,  # Number of sectors (~100 KB)
    )
    image[446:462] = part_entry

    # Add a mock FAT32 Volume Boot Record (VBR) at sector 32 (offset 32 * 512 = 16384)
    vbr_offset = 32 * 512
    image[vbr_offset : vbr_offset + 3] = b"\xeb\x58\x90"  # Jump instruction
    image[vbr_offset + 3 : vbr_offset + 11] = b"MSDOS5.0"  # OEM Name
    image[vbr_offset + 510 : vbr_offset + 512] = b"\x55\xaa"  # VBR signature

    out_path.write_bytes(bytes(image))


def generate_gpt_ext4(out_path: Path, size_kb: int = 128) -> None:
    """Generates a synthetic GPT disk image containing a Linux ext4 partition."""
    sector_size = 512
    total_sectors = (size_kb * 1024) // sector_size
    image = bytearray(total_sectors * sector_size)

    # Sector 0: Protective MBR
    image[510:512] = b"\x55\xaa"
    # Protective entry at offset 446: type 0xEE, covers entire disk
    protective_part = struct.pack(
        "<BBBBBBBBII",
        0x00,
        0x00,
        0x02,
        0x00,
        0xEE,  # GPT Protective MBR
        0xFF,
        0xFF,
        0xFF,
        1,  # Start LBA
        total_sectors - 1,
    )
    image[446:462] = protective_part

    # Sector 2..33: Partition Entry Array (128 entries * 128 bytes = 16,384 bytes = 32 sectors)
    part_entry_lba = 2
    num_entries = 128
    entry_size = 128
    entries_bytes = bytearray(num_entries * entry_size)

    # Partition 1: Linux Filesystem Data (UUID: 0FC63DAF-8483-4772-8E79-3D69D8477DE4)
    linux_fs_guid_le = uuid.UUID("0FC63DAF-8483-4772-8E79-3D69D8477DE4").bytes_le
    unique_part_guid_le = uuid.UUID("11223344-5566-7788-99AA-BBCCDDEEFF00").bytes_le
    start_lba = 34
    end_lba = total_sectors - 34
    flags = 0
    name_bytes = "root_ext4".encode("utf-16le").ljust(72, b"\x00")

    entry_data = struct.pack(
        "<16s16sQQQ72s",
        linux_fs_guid_le,
        unique_part_guid_le,
        start_lba,
        end_lba,
        flags,
        name_bytes,
    )
    entries_bytes[0:128] = entry_data

    # Copy partition array to Sector 2
    image[part_entry_lba * sector_size : (part_entry_lba * sector_size) + len(entries_bytes)] = entries_bytes

    # Calculate CRC32 of partition array
    part_array_crc = zlib.crc32(entries_bytes) & 0xFFFFFFFF

    # Sector 1: GPT Header (92 bytes)
    hdr_sig = b"EFI PART"
    revision = 0x00010000  # Revision 1.0
    hdr_size = 92
    reserved = 0
    curr_lba = 1
    backup_lba = total_sectors - 1
    first_usable_lba = 34
    last_usable_lba = total_sectors - 34
    disk_guid_le = uuid.UUID("A0B1C2D3-E4F5-6789-0123-456789ABCDEF").bytes_le

    # Build header with 0 for CRC32 field to calculate header CRC
    header_raw = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        hdr_sig,
        revision,
        hdr_size,
        0,  # temporary CRC
        reserved,
        curr_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
        disk_guid_le,
        part_entry_lba,
        num_entries,
        entry_size,
        part_array_crc,
    )
    hdr_crc = zlib.crc32(header_raw) & 0xFFFFFFFF

    # Repack with calculated CRC32
    header_final = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        hdr_sig,
        revision,
        hdr_size,
        hdr_crc,
        reserved,
        curr_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
        disk_guid_le,
        part_entry_lba,
        num_entries,
        entry_size,
        part_array_crc,
    )
    image[sector_size : sector_size + 92] = header_final

    out_path.write_bytes(bytes(image))


def generate_raw_unpartitioned(out_path: Path, size_kb: int = 64) -> None:
    """Generates an unpartitioned raw bitstream disk dump without partition table signatures."""
    total_bytes = size_kb * 1024
    image = bytearray(total_bytes)

    header_text = (
        b"DFT FORENSIC RAW BITSTREAM DUMP (UNPARTITIONED MEMORY / HEAP SLACK)\n"
        b"Device: /dev/sdb (Raw Flash Volume)\n"
        b"Acquisition: Direct physical stream, zero partition table headers.\n"
        b"Integrity Tag: DFT-SYNTHETIC-RAW-SAMPLE-01\n"
    )
    image[0 : len(header_text)] = header_text
    # Deliberately ensure bytes 510-511 are zero (no MBR signature)
    image[510:512] = b"\x00\x00"

    out_path.write_bytes(bytes(image))


def generate_corrupt_header(out_path: Path, size_kb: int = 64) -> None:
    """Generates a disk image with a damaged GPT header to test warning generation."""
    sector_size = 512
    total_bytes = size_kb * 1024
    image = bytearray(total_bytes)

    # Valid MBR protective header
    image[510:512] = b"\x55\xaa"

    # Damaged GPT Header in Sector 1: Signature present, but invalid/unusual header size and truncated partition table
    hdr_sig = b"EFI PART"
    revision = 0x00010000
    hdr_size = 64  # Invalid size (< 92 bytes)
    hdr_crc = 0xDEADBEEF
    reserved = 0
    curr_lba = 1
    backup_lba = 9999999  # Out of range
    first_usable_lba = 34
    last_usable_lba = 10000000
    disk_guid_le = b"\xff" * 16
    part_entry_lba = 2
    num_entries = 128  # Claims 128 entries (16KB), but file is truncated
    entry_size = 128
    part_crc = 0xCAFEBABE

    header_damaged = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        hdr_sig,
        revision,
        hdr_size,
        hdr_crc,
        reserved,
        curr_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
        disk_guid_le,
        part_entry_lba,
        num_entries,
        entry_size,
        part_crc,
    )
    image[sector_size : sector_size + 92] = header_damaged

    out_path.write_bytes(bytes(image))


def make_all_sample_images(output_dir: Path | None = None) -> dict[str, Path]:
    """Generates all 4 sample forensic disk images into the specified directory."""
    if output_dir is None:
        output_dir = Path(__file__).resolve().parent.parent / "sample_data"
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "mbr_fat": output_dir / "mbr_fat.img",
        "gpt_ext4": output_dir / "gpt_ext4.img",
        "raw_unpartitioned": output_dir / "raw_unpartitioned.dd",
        "corrupt_header": output_dir / "corrupt_header.img",
    }

    generate_mbr_fat(paths["mbr_fat"])
    generate_gpt_ext4(paths["gpt_ext4"])
    generate_raw_unpartitioned(paths["raw_unpartitioned"])
    generate_corrupt_header(paths["corrupt_header"])

    return paths


if __name__ == "__main__":
    generated = make_all_sample_images()
    print("Generated synthetic forensic sample disk images:")
    for key, path in generated.items():
        print(f"  • {key}: {path.name} ({path.stat().st_size} bytes)")
