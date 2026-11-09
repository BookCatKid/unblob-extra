import struct
from pathlib import Path

import pytest
from unblob.file_utils import File, InvalidInputFormat

from unblob_extra.handlers.chromium_pak import (
    ChromiumPakHandler,
    PakExtractor,
    PakParser,
)

handler = ChromiumPakHandler()

UTF8 = 1
RES_A = b"hello pak"
RES_B = bytes(range(64))
RES_C = b""  # empty resources are legal


def make_pak_v5(resources: dict, encoding: int = UTF8) -> bytes:
    """Mirror of grit's WriteDataPackToString (v5, with alias dedup)."""
    resource_ids = sorted(resources)
    id_by_data = {resources[k]: k for k in reversed(resource_ids)}
    alias_map = {k: id_by_data[v] for k, v in resources.items() if id_by_data[v] != k}
    resource_count = len(resources) - len(alias_map)

    out = [struct.pack("<IBxxxHH", 5, encoding, resource_count, len(alias_map))]
    data_offset = 12 + (resource_count + 1) * 6 + len(alias_map) * 4

    index_by_id = {}
    deduped = []
    for rid in resource_ids:
        if rid in alias_map:
            continue
        data = resources[rid]
        index_by_id[rid] = len(index_by_id)
        out.append(struct.pack("<HI", rid, data_offset))
        data_offset += len(data)
        deduped.append(data)
    out.append(struct.pack("<HI", 0, data_offset))
    for rid in sorted(alias_map):
        out.append(struct.pack("<HH", rid, index_by_id[alias_map[rid]]))
    out.extend(deduped)
    return b"".join(out)


def make_pak_v4(resources: dict, encoding: int = UTF8) -> bytes:
    """v4: 9-byte header, u32 count, u8 encoding, no alias table."""
    resource_ids = sorted(resources)
    out = [struct.pack("<IIB", 4, len(resource_ids), encoding)]
    data_offset = 9 + (len(resource_ids) + 1) * 6
    deduped = []
    for rid in resource_ids:
        data = resources[rid]
        out.append(struct.pack("<HI", rid, data_offset))
        data_offset += len(data)
        deduped.append(data)
    out.append(struct.pack("<HI", 0, data_offset))
    out.extend(deduped)
    return b"".join(out)


SIMPLE = make_pak_v5({10: RES_A, 20: RES_B, 30: RES_A, 40: RES_C})
V4 = make_pak_v4({7: RES_A, 42: RES_B})


def _extract(tmp_path: Path, blob: bytes):
    inpath = tmp_path / "in.pak"
    inpath.write_bytes(blob)
    outdir = tmp_path / "out"
    outdir.mkdir()
    return PakExtractor().extract(inpath, outdir), outdir


class TestChunk:
    def test_simple_chunk(self):
        chunk = handler.calculate_chunk(File.from_bytes(SIMPLE), 0)
        assert chunk is not None
        assert chunk.end_offset == len(SIMPLE)

    def test_v4_chunk(self):
        chunk = handler.calculate_chunk(File.from_bytes(V4), 0)
        assert chunk is not None
        assert chunk.end_offset == len(V4)

    def test_embedded_chunk(self):
        prefix = b"\x99" * 47
        chunk = handler.calculate_chunk(File.from_bytes(prefix + SIMPLE), len(prefix))
        assert chunk is not None
        assert chunk.end_offset == len(prefix) + len(SIMPLE)

    def test_empty_pak(self):
        # real locale stub paks ship zero resources: header + one
        # trailing index entry pointing at the (empty) data region
        blob = make_pak_v5({})
        chunk = handler.calculate_chunk(File.from_bytes(blob), 0)
        assert chunk is not None
        assert chunk.end_offset == len(blob)

    @pytest.mark.parametrize(
        "blob",
        [
            # wrong version
            struct.pack("<I", 6) + SIMPLE[4:],
            # encoding above 2 (v5)
            struct.pack("<IB", 5, 9) + SIMPLE[5:],
            # encoding above 2 (v4)
            struct.pack("<IIB", 4, 3, 9) + V4[9:],
            # table sizes that don't fit in the file
            SIMPLE[: len(SIMPLE) // 2],
            # first data offset not at the table end
            SIMPLE[:16] + struct.pack("<HI", 10, 0) + SIMPLE[22:],
            # index offsets out of order
            SIMPLE[:22] + struct.pack("<HI", 20, 0xFFFF) + SIMPLE[28:],
            # resource data beyond EOF
            SIMPLE[:-8],
        ],
        ids=[
            "bad-version",
            "bad-encoding-v5",
            "bad-encoding-v4",
            "tables-beyond-file",
            "data-offset-mismatch",
            "unordered-offsets",
            "truncated-data",
        ],
    )
    def test_rejects_malformed(self, blob):
        with pytest.raises(InvalidInputFormat):
            handler.calculate_chunk(File.from_bytes(blob), 0)

    def test_rejects_alias_out_of_range(self):
        # alias entry_index beyond the resource table
        blob = bytearray(SIMPLE)
        # locate the alias table: header 12 + (3+1)*6
        alias_off = 12 + 4 * 6
        struct.pack_into("<HH", blob, alias_off, 30, 99)
        with pytest.raises(InvalidInputFormat):
            handler.calculate_chunk(File.from_bytes(bytes(blob)), 0)


class TestExtraction:
    def test_resources_and_alias(self, tmp_path: Path):
        result, outdir = _extract(tmp_path, SIMPLE)
        assert (outdir / "10").read_bytes() == RES_A
        assert (outdir / "20").read_bytes() == RES_B
        assert (outdir / "40").read_bytes() == RES_C
        # id 30 aliases id 10: same content, separate file
        assert (outdir / "30").read_bytes() == RES_A
        assert result.reports == []

    def test_v4_extraction(self, tmp_path: Path):
        result, outdir = _extract(tmp_path, V4)
        assert (outdir / "7").read_bytes() == RES_A
        assert (outdir / "42").read_bytes() == RES_B
        assert result.reports == []

    def test_empty_resource_writes_empty_file(self, tmp_path: Path):
        _, outdir = _extract(tmp_path, SIMPLE)
        assert (outdir / "40").exists()
        assert (outdir / "40").stat().st_size == 0


class TestParser:
    def test_parses_header_fields(self):
        parser = PakParser(File.from_bytes(SIMPLE))
        assert parser.version == 5
        assert parser.encoding == UTF8
        assert parser.resource_count == 3  # 30 is an alias, not counted
        assert parser.alias_count == 1

    def test_parser_resources(self):
        parser = PakParser(File.from_bytes(SIMPLE))
        ids = [r.resource_id for r in parser.iter_resources()]
        assert ids == [10, 20, 40, 30]
