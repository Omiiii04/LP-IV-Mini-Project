import pytest

from services.disk_image_analyzer import examine


def test_disk_image_hashes_supported_read_only_image(tmp_path):
    image = tmp_path / "image.dd"
    image.write_bytes(b"synthetic image")
    result = examine(image)
    assert result["read_only"] is True
    assert len(result["sha256_before"]) == 64


def test_disk_image_rejects_unsupported_format(tmp_path):
    image = tmp_path / "image.bin"
    image.write_bytes(b"not an image")
    with pytest.raises(ValueError, match="unsupported"):
        examine(image)


def test_disk_image_metadata_is_persisted(client, app):
    import io
    import re

    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', client.get("/cases/new").data.decode()).group(
        1
    )
    client.post("/cases", data={"title": "Image review", "investigator": "Analyst", "csrf_token": token})
    with app.app_context():
        from models import Case

        case_id = Case.query.one().id
    response = client.post(
        "/disk-images",
        data={"case_id": str(case_id), "file": (io.BytesIO(b"synthetic image"), "image.dd"), "csrf_token": token},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    with app.app_context():
        from models import DiskImage

        item = DiskImage.query.one()
        assert item.sha256 == response.json["sha256_before"]
        assert item.analysis_status == "hash_only"


def test_gpt_partition_parsing_with_synthetic_image(tmp_path):
    import struct
    import uuid

    # Build synthetic 512-byte sector GPT disk image
    sector_size = 512
    img_data = bytearray(sector_size * 34)

    # LBA 0: Protective MBR
    img_data[510:512] = b"\x55\xaa"
    # MBR partition entry at 446
    img_data[446 : 446 + 16] = struct.pack("<BBBBBBBBII", 0, 0, 0, 0, 0xEE, 0, 0, 0, 1, 33)

    # LBA 1: GPT Header (92 bytes)
    disk_guid = uuid.UUID("12345678-1234-5678-1234-567812345678").bytes_le
    gpt_header = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART",  # Signature
        0x00010000,  # Revision
        92,  # Header size
        0,  # Header CRC32 placeholder
        0,  # Reserved
        1,  # Current LBA
        33,  # Backup LBA
        34,  # First usable LBA
        33,  # Last usable LBA
        disk_guid,  # Disk GUID
        2,  # Partition entry LBA
        2,  # Number of entries
        128,  # Entry size
        0,  # Entry array CRC32
    )
    img_data[512 : 512 + len(gpt_header)] = gpt_header

    # LBA 2: Partition entries (128 bytes each)
    # Entry 1: Linux Filesystem: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
    linux_fs_guid = uuid.UUID("0FC63DAF-8483-4772-8E79-3D69D8477DE4").bytes_le
    part1_guid = uuid.uuid4().bytes_le
    name1 = "rootfs".encode("utf-16le").ljust(72, b"\x00")
    entry1 = struct.pack("<16s16sQQQ72s", linux_fs_guid, part1_guid, 2048, 4095, 0, name1)
    img_data[1024 : 1024 + 128] = entry1

    # Entry 2: EFI System Partition: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
    efi_guid = uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").bytes_le
    part2_guid = uuid.uuid4().bytes_le
    name2 = "EFI System".encode("utf-16le").ljust(72, b"\x00")
    entry2 = struct.pack("<16s16sQQQ72s", efi_guid, part2_guid, 1024, 2047, 0, name2)
    img_data[1152 : 1152 + 128] = entry2

    gpt_img_path = tmp_path / "gpt_test.img"
    gpt_img_path.write_bytes(bytes(img_data))

    res = examine(gpt_img_path)
    assert res["scheme"] == "GPT (GUID Partition Table)"
    assert len(res["partitions"]) == 2
    assert res["partitions"][0]["name"] == "rootfs"
    assert "Linux" in res["partitions"][0]["type_name"]
    assert res["partitions"][1]["name"] == "EFI System"
    assert "EFI" in res["partitions"][1]["type_name"]
    assert "warnings" in res
    assert isinstance(res["warnings"], list)


def test_gpt_4096_sector_support(tmp_path):
    import struct
    import uuid

    sector_size = 4096
    img_data = bytearray(sector_size * 6)

    # Protective MBR at LBA 0 (first 512 bytes)
    img_data[510:512] = b"\x55\xaa"
    img_data[446 : 446 + 16] = struct.pack("<BBBBBBBBII", 0, 0, 0, 0, 0xEE, 0, 0, 0, 1, 5)

    # LBA 1 at byte offset 4096
    disk_guid = uuid.uuid4().bytes_le
    gpt_header = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART",
        0x00010000,
        92,
        0,
        0,
        1,
        5,
        6,
        5,
        disk_guid,
        2,  # partition entries at LBA 2 (byte 8192)
        1,
        128,
        0,
    )
    img_data[4096 : 4096 + len(gpt_header)] = gpt_header

    ms_basic_data = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").bytes_le
    name = "DataPart".encode("utf-16le").ljust(72, b"\x00")
    entry = struct.pack("<16s16sQQQ72s", ms_basic_data, uuid.uuid4().bytes_le, 100, 200, 0, name)
    img_data[8192 : 8192 + 128] = entry

    path = tmp_path / "gpt_4k.img"
    path.write_bytes(bytes(img_data))

    res = examine(path)
    assert res["scheme"] == "GPT (GUID Partition Table)"
    assert len(res["partitions"]) == 1
    assert res["partitions"][0]["name"] == "DataPart"
    assert "Basic Data" in res["partitions"][0]["type_name"] or "Microsoft" in res["partitions"][0]["type_name"]


def test_sample_data_mbr_fat_image(sample_data):
    mbr_path = sample_data / "mbr_fat.img"
    assert mbr_path.exists()
    res = examine(mbr_path)
    assert res["scheme"] == "MBR (Master Boot Record)"
    assert len(res["partitions"]) == 1
    assert "FAT32" in res["partitions"][0]["type_name"]
    assert res["partitions"][0]["bootable"] is True


def test_sample_data_gpt_ext4_image(sample_data):
    gpt_path = sample_data / "gpt_ext4.img"
    assert gpt_path.exists()
    res = examine(gpt_path)
    assert res["scheme"] == "GPT (GUID Partition Table)"
    assert len(res["partitions"]) == 1
    assert "Linux" in res["partitions"][0]["type_name"]
    assert res["partitions"][0]["name"] == "root_ext4"


def test_sample_data_raw_unpartitioned_image(sample_data):
    raw_path = sample_data / "raw_unpartitioned.dd"
    assert raw_path.exists()
    res = examine(raw_path)
    assert res["scheme"] == "Raw / Non-partitioned"
    assert res["partitions"] == []


def test_sample_data_corrupt_header_warnings(sample_data):
    corrupt_path = sample_data / "corrupt_header.img"
    assert corrupt_path.exists()
    res = examine(corrupt_path)
    # Never raise silent crashes; structured warnings must be populated
    assert isinstance(res["warnings"], list)
    assert len(res["warnings"]) > 0
    assert any("GPT" in w for w in res["warnings"])
