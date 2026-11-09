import json
import os
import stat
import struct
from pathlib import Path

import pytest
from unblob.file_utils import File, InvalidInputFormat

from unblob_extra.handlers.asar import (
    AsarExtractor,
    AsarHandler,
    _align4,
    _entry_path,
)

handler = AsarHandler()

CONTENT_A = b"console.log('hello');\n"
CONTENT_B = bytes(range(256)) * 4


def _insert(tree: dict, path: str, node: dict):
    parts = path.split("/")
    d = tree
    for part in parts[:-1]:
        d = d.setdefault(part, {"files": {}})["files"]
    d[parts[-1]] = node


def packed_tree(*items) -> tuple[dict, bytes]:
    """(name, content) pairs -> index tree + concatenated data blob."""
    tree, data = {}, bytearray()
    for name, content in items:
        node = {"size": len(content), "offset": str(len(data))}
        data += content
        _insert(tree, name, node)
    return tree, bytes(data)


def make_asar(tree: dict, data: bytes = b"", *, index: dict | None = None) -> bytes:
    index = {"files": tree} if index is None else index
    json_bytes = json.dumps(index, separators=(",", ":")).encode()
    payload = struct.pack("<I", len(json_bytes)) + json_bytes
    payload += b"\x00" * (-len(payload) % 4)
    return struct.pack("<III", 4, 4 + len(payload), len(payload)) + payload + data


SIMPLE_TREE, SIMPLE_DATA = packed_tree(
    ("app/main.js", CONTENT_A), ("app/lib/util.js", CONTENT_B)
)
SIMPLE = make_asar(SIMPLE_TREE, SIMPLE_DATA)


def _extract(tmp_path: Path, blob: bytes, name: str = "in.asar"):
    inpath = tmp_path / name
    inpath.write_bytes(blob)
    outdir = tmp_path / "out"
    outdir.mkdir()
    return AsarExtractor().extract(inpath, outdir), inpath, outdir


class TestFraming:
    def test_simple_chunk(self):
        chunk = handler.calculate_chunk(File.from_bytes(SIMPLE), 0)
        assert chunk is not None
        assert chunk.end_offset == len(SIMPLE)

    def test_embedded_chunk(self):
        prefix = b"\xaa" * 33
        chunk = handler.calculate_chunk(File.from_bytes(prefix + SIMPLE), len(prefix))
        assert chunk is not None
        assert chunk.start_offset == len(prefix)
        assert chunk.end_offset == len(prefix) + len(SIMPLE)

    @pytest.mark.parametrize(
        "blob",
        [
            # outer pickle size is always 4
            struct.pack("<I", 8) + SIMPLE[4:],
            # header_size must equal payload_size + 4
            SIMPLE[:4] + struct.pack("<I", len(SIMPLE)) + SIMPLE[8:],
            # payload_size must hold the aligned JSON
            SIMPLE[:8] + struct.pack("<I", 0x40) + SIMPLE[12:],
            # zero-length JSON
            SIMPLE[:12] + struct.pack("<I", 0) + SIMPLE[16:],
            # non-JSON payload
            SIMPLE[:16] + b"not json at all" + b"\x00" * 17,
            # index without a top-level files object
            make_asar({}, index={"not_files": {}}),
            # files is not an object
            make_asar({}, index={"files": ["a"]}),
        ],
        ids=[
            "bad-outer-size",
            "header-payload-mismatch",
            "payload-json-mismatch",
            "empty-json",
            "non-json",
            "no-files-object",
            "files-not-object",
        ],
    )
    def test_rejects_malformed_framing(self, blob):
        with pytest.raises(InvalidInputFormat):
            handler.calculate_chunk(File.from_bytes(blob), 0)


class TestIndex:
    @pytest.mark.parametrize(
        "tree,data",
        [
            # entry that is not an object
            ({"a": 42}, b""),
            # entry of unknown kind
            ({"a": {"wat": 1}}, b""),
            # directory whose files is not an object
            ({"a": {"files": 3}}, b""),
            # link without a string target
            ({"a": {"link": 12}}, b""),
            # negative size
            ({"a": {"size": -1, "offset": "0"}}, b""),
            # non-numeric size
            ({"a": {"size": "big", "offset": "0"}}, b""),
            # unparseable offset
            ({"a": {"size": 1, "offset": "x"}}, b""),
            # negative offset
            ({"a": {"size": 1, "offset": "-4"}}, b""),
        ],
        ids=[
            "non-object-entry",
            "unknown-kind",
            "bad-dir",
            "bad-link",
            "negative-size",
            "non-numeric-size",
            "bad-offset",
            "negative-offset",
        ],
    )
    def test_rejects_malformed_entries(self, tree, data):
        with pytest.raises(InvalidInputFormat):
            handler.calculate_chunk(File.from_bytes(make_asar(tree, data)), 0)

    def test_member_beyond_eof(self):
        blob = make_asar({"a": {"size": 100, "offset": "0"}}, b"short")
        with pytest.raises(InvalidInputFormat):
            handler.calculate_chunk(File.from_bytes(blob), 0)

    def test_empty_archive(self):
        blob = make_asar({})
        chunk = handler.calculate_chunk(File.from_bytes(blob), 0)
        assert chunk is not None
        assert chunk.end_offset == len(blob)

    def test_offset_gap_is_inside_chunk(self):
        tree = {"a": {"size": 4, "offset": "10"}}
        data = b"\x00" * 10 + b"data"
        blob = make_asar(tree, data)
        chunk = handler.calculate_chunk(File.from_bytes(blob), 0)
        assert chunk is not None
        assert chunk.end_offset == len(blob)


class TestExtraction:
    def test_nested_files(self, tmp_path: Path):
        result, _, outdir = _extract(tmp_path, SIMPLE)
        assert (outdir / "app/main.js").read_bytes() == CONTENT_A
        assert (outdir / "app/lib/util.js").read_bytes() == CONTENT_B
        assert result.reports == []

    def test_empty_dir_created(self, tmp_path: Path):
        blob = make_asar({"empty": {"files": {}}})
        _, _, outdir = _extract(tmp_path, blob)
        assert (outdir / "empty").is_dir()

    def test_executable_bit(self, tmp_path: Path):
        tree, data = packed_tree(("run.sh", CONTENT_A))
        tree["run.sh"]["executable"] = True
        _, _, outdir = _extract(tmp_path, make_asar(tree, data))
        mode = stat.S_IMODE((outdir / "run.sh").stat().st_mode)
        assert mode == 0o755

    def test_integrity_ok(self, tmp_path: Path):
        import hashlib

        tree, data = packed_tree(("f.bin", CONTENT_B))
        tree["f.bin"]["integrity"] = {
            "algorithm": "SHA256",
            "hash": hashlib.sha256(CONTENT_B).hexdigest(),
            "blockSize": 4194304,
            "blocks": [],
        }
        result, _, outdir = _extract(tmp_path, make_asar(tree, data))
        assert (outdir / "f.bin").read_bytes() == CONTENT_B
        assert result.reports == []

    def test_integrity_mismatch(self, tmp_path: Path):
        tree, data = packed_tree(("f.bin", CONTENT_B))
        tree["f.bin"]["integrity"] = {
            "algorithm": "SHA256",
            "hash": "0" * 64,
        }
        result, _, outdir = _extract(tmp_path, make_asar(tree, data))
        assert (outdir / "f.bin").read_bytes() == CONTENT_B
        assert len(result.reports) == 1
        assert "integrity" in result.reports[0].problem

    def test_link_entry(self, tmp_path: Path):
        # link targets are root-relative (Paseo.app's real layout:
        # node_modules/x/AGENTS.md -> "node_modules/x/CLAUDE.md")
        tree, data = packed_tree(("pkg/CLAUDE.md", CONTENT_A))
        _insert(tree, "pkg/AGENTS.md", {"link": "pkg/CLAUDE.md"})
        result, _, outdir = _extract(tmp_path, make_asar(tree, data))
        link = outdir / "pkg/AGENTS.md"
        assert link.is_symlink()
        assert os.readlink(link) == "CLAUDE.md"
        assert link.read_bytes() == CONTENT_A
        assert result.reports == []

    def test_unpacked_without_sibling(self, tmp_path: Path):
        tree, data = packed_tree(("packed.js", CONTENT_A))
        _insert(tree, "native.node", {"size": 99, "unpacked": True})
        result, _, outdir = _extract(tmp_path, make_asar(tree, data))
        assert (outdir / "packed.js").read_bytes() == CONTENT_A
        assert not (outdir / "native.node").exists()
        assert len(result.reports) == 1
        assert "npacked" in result.reports[0].problem

    def test_unpacked_with_sibling(self, tmp_path: Path):
        native = b"\xde\xad\xbe\xef" * 8
        tree, data = packed_tree(("packed.js", CONTENT_A))
        _insert(tree, "native.node", {"size": len(native), "unpacked": True})
        inpath = tmp_path / "in.asar"
        inpath.write_bytes(make_asar(tree, data))
        sibling_root = tmp_path / "in.asar.unpacked"
        sibling_root.mkdir()
        (sibling_root / "native.node").write_bytes(native)
        outdir = tmp_path / "out"
        outdir.mkdir()

        result = AsarExtractor().extract(inpath, outdir)

        assert (outdir / "packed.js").read_bytes() == CONTENT_A
        assert (outdir / "native.node").read_bytes() == native
        assert result.reports == []

    def test_entry_beyond_eof_skipped(self, tmp_path: Path):
        tree, data = packed_tree(("ok.js", CONTENT_A))
        _insert(tree, "bad.js", {"size": 10_000, "offset": "0"})
        result, _, outdir = _extract(tmp_path, make_asar(tree, data))
        assert (outdir / "ok.js").read_bytes() == CONTENT_A
        assert not (outdir / "bad.js").exists()
        assert any("beyond the archive" in r.problem for r in result.reports)

    def test_traversal_name_sanitized(self, tmp_path: Path):
        # the raw index key "../evil" cannot escape the extraction dir
        tree, data = packed_tree(("../evil.js", CONTENT_A))
        result, _, outdir = _extract(tmp_path, make_asar(tree, data))
        assert not (tmp_path / "evil.js").exists()
        assert (outdir / "evil.js").read_bytes() == CONTENT_A


class TestHelpers:
    def test_align4(self):
        assert [_align4(n) for n in (0, 1, 3, 4, 5, 7)] == [0, 4, 4, 4, 8, 8]

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("a/b/c.js", "a/b/c.js"),
            ("a\\b\\c.js", "a/b/c.js"),
            ("..", None),
            (".", None),
            ("a/../b", "a/b"),
        ],
    )
    def test_entry_path(self, raw, expected):
        from pathlib import PurePosixPath

        out = _entry_path(PurePosixPath(raw))
        assert (None if out is None else out.as_posix()) == expected
