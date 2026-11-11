"""Proven recovery of FAT16 images that omit only unallocated trailing space."""

import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from unblob.file_utils import File, InvalidInputFormat

from unblob_extra.handlers.irobot.compact_fat16 import (
    CompactFat16Extractor,
    CompactFat16Handler,
    _logical_size,
)


@pytest.fixture
def compact_fat16() -> bytes:
    """A minimal *synthetic* valid FAT16 containing image/HELLO.TXT.

    The boot sector describes 8192 sectors (4 MiB), but the archived physical
    bytes end at the last allocated cluster. No vendor firmware is bundled.
    """
    sector_size = 512
    total_sectors = 8192
    fat_sectors = 32
    reserved = 1
    fat_copies = 2
    root_sectors = 32
    fat_offset = sector_size
    root_offset = (reserved + fat_copies * fat_sectors) * sector_size
    data_offset = root_offset + root_sectors * sector_size
    # The two allocated clusters are #2 (directory) and #3 (file).
    physical_end = data_offset + (3 - 1) * sector_size
    data = bytearray(physical_end)
    data[:3] = b"\xeb\x3c\x90"
    data[3:11] = b"MSDOS5.0"
    struct.pack_into(
        "<HBHBHHBHHHII",
        data,
        11,
        sector_size,
        1,
        reserved,
        fat_copies,
        512,
        total_sectors,
        0xF8,
        fat_sectors,
        63,
        255,
        0,
        0,
    )
    data[36] = 0x80  # drive number
    data[38] = 0x29  # extended boot signature
    data[39:43] = b"\x12\x34\x56\x78"
    data[43:54] = b"NO NAME    "
    data[54:62] = b"FAT16   "
    data[510:512] = b"\x55\xaa"

    fat = bytearray(fat_sectors * sector_size)
    for idx, value in enumerate((0xFFF8, 0xFFFF, 0xFFFF, 0xFFFF)):
        struct.pack_into("<H", fat, 2 * idx, value)
    data[fat_offset : fat_offset + len(fat)] = fat
    data[fat_offset + len(fat) : fat_offset + 2 * len(fat)] = fat

    def directory_entry(
        at: int, name: bytes, ext: bytes, flags: int, first_cluster: int, length: int
    ):
        data[at : at + 11] = name.ljust(8, b" ") + ext.ljust(3, b" ")
        data[at + 11] = flags
        struct.pack_into("<HI", data, at + 26, first_cluster, length)

    directory_entry(root_offset, b"IMAGE", b"", 0x10, 2, 0)
    directory_entry(data_offset, b".", b"", 0x10, 2, 0)
    directory_entry(data_offset + 32, b"..", b"", 0x10, 0, 0)
    payload = b"Verified firmware FAT16\n"
    directory_entry(data_offset + 64, b"HELLO", b"TXT", 0x20, 3, len(payload))
    data[data_offset + sector_size : data_offset + sector_size + len(payload)] = payload
    return bytes(data)


def test_compact_fat16_geometry_is_consistent(tmp_path: Path, compact_fat16: bytes):
    assert len(compact_fat16) == 50688
    source = tmp_path / "compact.fat"
    source.write_bytes(compact_fat16)
    with File.from_path(source) as inp:
        assert _logical_size(inp, 0) == 4194304
        chunk = CompactFat16Handler().calculate_chunk(inp, 0)
        assert chunk is not None
        assert (chunk.start_offset, chunk.end_offset) == (0, len(compact_fat16))


@pytest.mark.parametrize("trim", [1, 511, 512])
def test_reject_fat16_missing_allocated_bytes(
    tmp_path: Path, compact_fat16: bytes, trim: int
):
    source = tmp_path / "truncated.fat"
    source.write_bytes(compact_fat16[:-trim])
    with File.from_path(source) as inp:
        with pytest.raises(InvalidInputFormat):
            CompactFat16Handler().calculate_chunk(inp, 0)


def test_full_length_fat16_falls_back_to_upstream(tmp_path: Path, compact_fat16: bytes):
    source = tmp_path / "full.fat"
    with source.open("wb") as out:
        out.write(compact_fat16)
        out.truncate(8192 * 512)
    with File.from_path(source) as inp:
        assert CompactFat16Handler().calculate_chunk(inp, 0) is None


def test_reject_fat16_without_credible_geometry(tmp_path: Path, compact_fat16: bytes):
    bad = bytearray(compact_fat16)
    bad[13] = 3  # sectors/cluster must be a power of two
    source = tmp_path / "corrupt.fat"
    source.write_bytes(bad)
    with File.from_path(source) as inp:
        with pytest.raises(InvalidInputFormat):
            CompactFat16Handler().calculate_chunk(inp, 0)


def test_compact_fat16_extractor_preserves_original(
    tmp_path: Path, compact_fat16: bytes
):
    if not shutil.which("7z"):
        pytest.skip("Requires 7z, also needed by upstream FAT")
    source = tmp_path / "NON-HLOS.bin"
    source.write_bytes(compact_fat16)
    out = tmp_path / "files"
    out.mkdir()
    CompactFat16Extractor().extract(source, out)
    assert (out / "IMAGE" / "HELLO.TXT").read_bytes() == b"Verified firmware FAT16\n"
    assert source.read_bytes() == compact_fat16
    assert sorted(p.name for p in out.iterdir()) == ["IMAGE"]


def test_extractor_rejects_genuinely_truncated_image(
    tmp_path: Path, compact_fat16: bytes
):
    source = tmp_path / "truncated-fat16.bin"
    source.write_bytes(compact_fat16[:-512])
    dest = tmp_path / "output"
    dest.mkdir()
    with pytest.raises(InvalidInputFormat):
        CompactFat16Extractor().extract(source, dest)
    assert not any(dest.iterdir())


def test_plugin_preempts_builtin_fat_for_compact_image(
    tmp_path: Path, compact_fat16: bytes
):
    if not shutil.which("7z"):
        pytest.skip("Requires 7z, also needed by upstream FAT")
    source = tmp_path / "NON-HLOS.bin"
    source.write_bytes(compact_fat16)
    output = tmp_path / "unblob-output"
    report = tmp_path / "report.json"
    cmd = [
        str(Path(sys.executable).with_name("unblob")),
        "--no-sandbox",
        "--process-num",
        "1",
        "--randomness-depth",
        "0",
        "--depth",
        "1",
        "--extract-dir",
        str(output),
        "--report",
        str(report),
        "--log",
        str(tmp_path / "unblob.log"),
        str(source),
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr + completed.stdout
    reports = json.loads(report.read_text())
    chunk_handlers = {
        entry["handler_name"]
        for task in reports
        for entry in task.get("reports", [])
        if "handler_name" in entry
    }
    assert "irobot_compact_fat16" in chunk_handlers, chunk_handlers
    assert "fat" not in chunk_handlers, chunk_handlers
    assert (output / "NON-HLOS.bin_extract" / "IMAGE" / "HELLO.TXT").read_bytes() == (
        b"Verified firmware FAT16\n"
    )
