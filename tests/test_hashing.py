from pathlib import Path

from services.hashing import hash_bytes, hashes_match, multi_hash_file, sha256_bytes, sha256_file


def test_sha256_and_mismatch_detection(tmp_path: Path):
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"forensic evidence")
    digest = sha256_file(path)
    assert len(digest) == 64
    assert hashes_match(path, digest)
    assert not hashes_match(path, "0" * 64)


def test_empty_file_hashing(tmp_path: Path):
    empty_path = tmp_path / "empty.bin"
    empty_path.write_bytes(b"")
    result = multi_hash_file(empty_path)
    # Standard SHA-256 for empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert result["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert result["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert result["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_large_file_chunking(tmp_path: Path):
    # Create 2.5 MB file to exercise 1 MB chunk loop
    large_path = tmp_path / "large.bin"
    chunk = b"A" * (1024 * 1024)
    with large_path.open("wb") as f:
        f.write(chunk)
        f.write(chunk)
        f.write(b"B" * 512 * 1024)

    result = multi_hash_file(large_path)
    assert len(result["sha256"]) == 64
    assert hashes_match(large_path, result["sha256"])
    assert not hashes_match(large_path, result["sha256"][:-2] + "00")


def test_in_memory_byte_hashing():
    data = b"forensic memory slice"
    result = hash_bytes(data)
    assert len(result["sha256"]) == 64
    assert len(result["md5"]) == 32
    assert len(result["sha1"]) == 40
    assert sha256_bytes(data) == result["sha256"]
