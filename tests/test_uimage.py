import struct
import zlib
from pathlib import Path

import pytest
from unblob.file_utils import File, InvalidInputFormat

from unblob_extra.handlers.uimage import (
    UImageExtractor,
    UImageHandler,
    UImageParser,
)

handler = UImageHandler()

MAGIC = 0x27051956
PAYLOAD = b"\x1f\x8b\x08fake-kernel-payload" * 4


def make_uimage(
    payload: bytes = PAYLOAD,
    *,
    os_: int = 5,
    arch: int = 2,
    type_: int = 2,
    comp: int = 1,
    name: bytes = b"Linux-test",
    magic: int = MAGIC,
    fix_hcrc: bool = True,
    fix_dcrc: bool = True,
) -> bytes:
    dcrc = zlib.crc32(payload) if fix_dcrc else 0xDEADBEEF
    # mkimage computes hcrc over the header with ih_hcrc zeroed but the
    # real ih_dcrc already in place
    header = struct.pack(
        ">7I4B32s",
        magic,
        0,  # hcrc placeholder
        1_700_000_000,
        len(payload),
        0x8000,
        0x8000,
        dcrc,
        os_,
        arch,
        type_,
        comp,
        name.ljust(32, b"\x00"),
    )
    hcrc = zlib.crc32(header) if fix_hcrc else 0xDEADBEEF
    header = header[:4] + struct.pack(">I", hcrc) + header[8:]
    return header + payload


SIMPLE = make_uimage()


def make_multi(parts: list[bytes]) -> bytes:
    table = struct.pack(">I", len(parts)) + b"".join(
        struct.pack(">I", len(p)) for p in parts
    )
    return make_uimage(table + b"".join(parts), type_=4, comp=0, name=b"multi-fw")


def _extract(tmp_path: Path, blob: bytes):
    inpath = tmp_path / "in.uimage"
    inpath.write_bytes(blob)
    outdir = tmp_path / "out"
    outdir.mkdir()
    return UImageExtractor().extract(inpath, outdir), outdir


class TestChunk:
    def test_simple_chunk(self):
        chunk = handler.calculate_chunk(File.from_bytes(SIMPLE), 0)
        assert chunk is not None
        assert chunk.end_offset == len(SIMPLE)

    def test_embedded_chunk(self):
        prefix = b"\x11" * 51
        chunk = handler.calculate_chunk(File.from_bytes(prefix + SIMPLE), len(prefix))
        assert chunk is not None
        assert chunk.end_offset == len(prefix) + len(SIMPLE)

    @pytest.mark.parametrize(
        "blob",
        [
            # wrong magic
            make_uimage(magic=0xDEADBEEF),
            # header CRC zeroed/garbage
            make_uimage(fix_hcrc=False),
            # payload CRC wrong
            make_uimage(fix_dcrc=False),
            # empty payload
            make_uimage(payload=b""),
            # payload beyond EOF
            make_uimage()[:-16],
            # enum field out of range
            make_uimage(os_=0x99),
            make_uimage(arch=0x99),
            make_uimage(type_=0x99),
            make_uimage(comp=0x99),
        ],
        ids=[
            "bad-magic",
            "bad-hcrc",
            "bad-dcrc",
            "empty-payload",
            "truncated-payload",
            "bad-os",
            "bad-arch",
            "bad-type",
            "bad-comp",
        ],
    )
    def test_rejects_malformed(self, blob):
        with pytest.raises(InvalidInputFormat):
            handler.calculate_chunk(File.from_bytes(blob), 0)


class TestExtraction:
    def test_payload_named_with_comp_suffix(self, tmp_path: Path):
        result, outdir = _extract(tmp_path, SIMPLE)
        assert (outdir / "Linux-test.gz").read_bytes() == PAYLOAD
        assert result.reports == []

    def test_uncompressed_no_suffix(self, tmp_path: Path):
        blob = make_uimage(comp=0, name=b"initrd")
        _, outdir = _extract(tmp_path, blob)
        assert (outdir / "initrd").read_bytes() == PAYLOAD

    def test_empty_name_fallback(self, tmp_path: Path):
        blob = make_uimage(name=b"")
        _, outdir = _extract(tmp_path, blob)
        assert (outdir / "uImage.gz").read_bytes() == PAYLOAD

    def test_name_sanitized(self, tmp_path: Path):
        blob = make_uimage(name=b"../../evil")
        _, outdir = _extract(tmp_path, blob)
        assert not (tmp_path / "evil.gz").exists()
        # '/' -> '_' and leading dots stripped
        assert (outdir / "_.._evil.gz").exists()

    def test_multi_members(self, tmp_path: Path):
        parts = [b"kernel-blob", b"fdt-blob", b"ramdisk-blob"]
        blob = make_multi(parts)
        result, outdir = _extract(tmp_path, blob)
        for i, part in enumerate(parts):
            assert (outdir / f"multi-fw.{i}").read_bytes() == part
        assert result.reports == []

    def test_multi_bad_count(self):
        blob = bytearray(make_multi([b"x"]))
        struct.pack_into(">I", blob, 64, 0)  # zero members
        # hcrc/dcrc still valid since payload untouched
        with pytest.raises(InvalidInputFormat):
            UImageParser(File.from_bytes(bytes(blob))).iter_members().__next__()


class TestParser:
    def test_header_fields(self):
        parser = UImageParser(File.from_bytes(SIMPLE))
        h = parser.header
        assert h.ih_magic == MAGIC
        assert h.ih_size == len(PAYLOAD)
        assert (h.ih_os, h.ih_arch, h.ih_type, h.ih_comp) == (5, 2, 2, 1)
        assert parser.image_name == "Linux-test"
