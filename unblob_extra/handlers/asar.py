"""Electron ASAR archives.

An ASAR file concatenates every JavaScript/source asset of an Electron app
into one blob. The layout is Chromium pickle framing (little-endian) holding a
JSON index, followed by the raw, uncompressed file payloads:

    u32 outer_pickle_size;   // always 4 (payload of the outer pickle)
    u32 header_size;         // 4 + inner pickle payload size
    u32 payload_size;        // header_size - 4
    u32 json_size;           // byte length of the JSON index
    u8  json[json_size];     // {"files":{...}}
    u8  pad[];               // JSON zero-padded to a 4-byte boundary
    u8  data[];              // concatenated payloads, base = offset + 8 + header_size

The index is ``{"files": {name: entry, ...}}`` where each entry is one of:

    directory  {"files": {name: entry, ...}}
    file       {"size": N, "offset": "<decimal>", "executable"?: true,
                "integrity"?: {"algorithm": "SHA256", "hash": "<hex>", ...}}
    symlink    {"link": "<path relative to the archive root>"}
    unpacked   {"size": N, "unpacked": true}   payload lives in the sibling
                                             ``<archive>.unpacked`` directory

Offsets are decimal *strings* relative to the data base. There is no magic;
the signature is the fixed 4-byte outer pickle size followed after three u32
size fields by the literal ``{"files":``.
"""

from __future__ import annotations

import io
import json
import posixpath
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from structlog import get_logger
from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    iterate_file,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    ValidChunk,
)
from unblob.report import ExtractionProblem

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct asar_framing {
        uint32 outer_pickle_size;   // always 4
        uint32 header_size;         // 4 + pickle payload size
        uint32 payload_size;        // header_size - 4
        uint32 json_size;           // byte length of the JSON index
    } asar_framing_t;
"""
ASAR_FRAMING = "asar_framing_t"
ASAR_FRAMING_SIZE = 0x10

OUTER_PICKLE_SIZE = 4
EXECUTABLE_MODE = 0o755
SHA256_HEX_LEN = 64


class _Entry:
    __slots__ = (
        "data_offset",
        "executable",
        "integrity_hash",
        "kind",
        "link",
        "path",
        "size",
    )

    def __init__(
        self,
        kind: str,
        path: PurePosixPath,
        *,
        data_offset: int = 0,
        size: int = 0,
        link: str = "",
        executable: bool = False,
        integrity_hash: str = "",
    ):
        self.kind = kind
        self.path = path
        self.data_offset = data_offset
        self.size = size
        self.link = link
        self.executable = executable
        self.integrity_hash = integrity_hash


def _align4(n: int) -> int:
    return (n + 3) & ~3


class AsarParser:
    """Parse the framing and index of an ASAR archive."""

    def __init__(self, file: File, start_offset: int = 0):
        self.file = file
        self.struct_parser = StructParser(C_DEFINITIONS)
        self.file.seek(start_offset, io.SEEK_SET)
        framing = self.struct_parser.parse(ASAR_FRAMING, file, Endian.LITTLE)
        self._validate_framing(framing)
        self.json_size = framing.json_size
        # file payloads start right after the framing and header pickle
        self.data_offset = start_offset + 8 + framing.header_size
        self.index = self._read_index(start_offset + ASAR_FRAMING_SIZE)

    @staticmethod
    def _validate_framing(framing):
        if framing.outer_pickle_size != OUTER_PICKLE_SIZE:
            raise InvalidInputFormat("not an ASAR outer pickle")
        if framing.header_size != framing.payload_size + 4:
            raise InvalidInputFormat("ASAR header/payload size mismatch")
        if framing.payload_size != 4 + _align4(framing.json_size):
            raise InvalidInputFormat("ASAR payload/JSON size mismatch")
        if framing.json_size == 0:
            raise InvalidInputFormat("empty ASAR index")

    def _read_index(self, json_offset: int) -> dict:
        if json_offset + self.json_size > self.file.size():
            raise InvalidInputFormat("ASAR index lies beyond the file")
        raw = bytes(self.file[json_offset : json_offset + self.json_size])
        try:
            index = json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            raise InvalidInputFormat("malformed ASAR JSON index") from None
        if not isinstance(index, dict) or not isinstance(index.get("files"), dict):
            raise InvalidInputFormat("ASAR index has no top-level files object")
        return index

    def iter_entries(self) -> Iterable[_Entry]:
        yield from self._walk(self.index["files"], PurePosixPath())

    def _walk(self, files: dict, prefix: PurePosixPath) -> Iterable[_Entry]:
        for name, entry in files.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                raise InvalidInputFormat("malformed ASAR index entry")
            path = prefix / name
            sub = entry.get("files")
            if sub is not None:
                if not isinstance(sub, dict):
                    raise InvalidInputFormat(
                        f"ASAR directory entry {path} is not an object"
                    )
                yield _Entry("dir", path)
                yield from self._walk(sub, path)
            elif "link" in entry:
                link = entry["link"]
                if not isinstance(link, str) or not link:
                    raise InvalidInputFormat(f"invalid ASAR link entry {path}")
                yield _Entry("link", path, link=link)
            elif entry.get("unpacked"):
                yield _Entry("unpacked", path, size=_entry_size(entry, path))
            elif "offset" in entry:
                size = _entry_size(entry, path)
                yield _Entry(
                    "file",
                    path,
                    data_offset=self.data_offset + _entry_offset(entry, path),
                    size=size,
                    executable=bool(entry.get("executable")),
                    integrity_hash=_integrity_hash(entry),
                )
            else:
                raise InvalidInputFormat(f"unknown ASAR entry kind at {path}")


def _entry_size(entry: dict, path: PurePosixPath) -> int:
    size = entry.get("size", 0)
    if not isinstance(size, int) or size < 0:
        raise InvalidInputFormat(f"invalid ASAR entry size at {path}")
    return size


def _entry_offset(entry: dict, path: PurePosixPath) -> int:
    # offsets are decimal strings in the official format; tolerate ints
    try:
        offset = int(entry["offset"])
    except (TypeError, ValueError):
        raise InvalidInputFormat(f"invalid ASAR entry offset at {path}") from None
    if offset < 0:
        raise InvalidInputFormat(f"negative ASAR entry offset at {path}")
    return offset


def _integrity_hash(entry: dict) -> str:
    integrity = entry.get("integrity")
    if not isinstance(integrity, dict):
        return ""
    if integrity.get("algorithm") != "SHA256":
        return ""
    digest = integrity.get("hash")
    if not isinstance(digest, str) or len(digest) != SHA256_HEX_LEN:
        return ""
    return digest


def _entry_path(path: PurePosixPath) -> Path | None:
    """Turn a JSON index path into a safe extraction path, or None."""
    parts = []
    for part in path.parts:
        # index keys are single names, but split defensively
        for piece in part.replace("\\", "/").split("/"):
            piece = piece.strip()
            if piece in ("", ".", ".."):
                continue
            parts.append(piece)
    if not parts:
        return None
    return Path(*parts)


class AsarExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        fs = FileSystem(outdir)
        # payloads of "unpacked" entries live in a sibling directory
        unpacked_root = inpath.parent / (inpath.name + ".unpacked")
        if not unpacked_root.is_dir():
            unpacked_root = None
        with File.from_path(inpath) as file:
            parser = AsarParser(file)
            for entry in parser.iter_entries():
                try:
                    self._extract_entry(file, fs, entry, unpacked_root)
                except OSError as e:
                    fs.record_problem(
                        ExtractionProblem(
                            problem=f"Failed to extract ASAR entry: {e}",
                            resolution="Skipped.",
                            path=str(entry.path),
                        )
                    )
        return ExtractResult(reports=fs.problems)

    def _extract_entry(
        self, file: File, fs: FileSystem, entry: _Entry, unpacked_root: Path | None
    ):
        out_path = _entry_path(entry.path)
        if out_path is None:
            fs.record_problem(
                ExtractionProblem(
                    problem="ASAR entry with unusable name",
                    resolution="Skipped.",
                    path=str(entry.path),
                )
            )
            return
        if entry.kind == "dir":
            fs.mkdir(out_path, parents=True, exist_ok=True)
        elif entry.kind == "link":
            self._extract_link(fs, entry, out_path)
        elif entry.kind == "unpacked":
            self._extract_unpacked(fs, entry, out_path, unpacked_root)
        else:
            self._extract_file(file, fs, entry, out_path)

    def _extract_file(self, file: File, fs: FileSystem, entry: _Entry, out_path: Path):
        if entry.data_offset + entry.size > file.size():
            fs.record_problem(
                ExtractionProblem(
                    problem="ASAR entry data lies beyond the archive",
                    resolution="Skipped.",
                    path=out_path.as_posix(),
                )
            )
            return
        fs.carve(out_path, file, entry.data_offset, entry.size)
        if entry.executable:
            fs.chmod(out_path, EXECUTABLE_MODE)
        if entry.integrity_hash:
            digest = sha256()
            for chunk in iterate_file(file, entry.data_offset, entry.size):
                digest.update(chunk)
            if digest.hexdigest() != entry.integrity_hash:
                fs.record_problem(
                    ExtractionProblem(
                        problem="ASAR entry failed its SHA256 integrity check",
                        resolution="Extracted anyway.",
                        path=out_path.as_posix(),
                    )
                )

    @staticmethod
    def _extract_link(fs: FileSystem, entry: _Entry, out_path: Path):
        # link targets are relative to the archive root; rewrite them
        # relative to the directory holding the symlink
        target = PurePosixPath("/") / entry.link
        parent = PurePosixPath("/") / entry.path.parent
        rel = posixpath.relpath(str(target), str(parent))
        fs.create_symlink(Path(rel), out_path)

    @staticmethod
    def _extract_unpacked(
        fs: FileSystem, entry: _Entry, out_path: Path, unpacked_root: Path | None
    ):
        if unpacked_root is None:
            fs.record_problem(
                ExtractionProblem(
                    problem="Unpacked ASAR entry, data is not stored in the archive",
                    resolution="Skipped.",
                    path=out_path.as_posix(),
                )
            )
            return
        sibling = unpacked_root / out_path
        if not sibling.is_file():
            fs.record_problem(
                ExtractionProblem(
                    problem="Unpacked ASAR entry missing from the sibling directory",
                    resolution="Skipped.",
                    path=out_path.as_posix(),
                )
            )
            return
        with File.from_path(sibling) as sib_file:
            fs.carve(out_path, sib_file, 0, min(entry.size, sib_file.size()))
        if entry.executable:
            fs.chmod(out_path, EXECUTABLE_MODE)


class AsarHandler(Handler):
    NAME = "asar"
    PATTERNS = [
        # outer pickle size (always 4), three u32 size fields, then
        # the literal start of the JSON index {"files":
        HexString("04 00 00 00 [12] 7b 22 66 69 6c 65 73 22 3a"),
    ]
    EXTRACTOR = AsarExtractor()
    DOC = HandlerDoc(
        name="Electron ASAR",
        description=(
            "Concatenated file payloads used to package Electron apps: a "
            "Chromium-pickle-framed JSON index (paths, sizes, offsets, "
            "SHA256 integrity) followed by raw uncompressed file data. "
            "Members marked unpacked live in a sibling ``.unpacked`` "
            "directory and are recovered from it when present."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="Electron",
        references=[
            Reference(
                title="electron/asar archive format and tooling",
                url="https://github.com/electron/asar",
            ),
        ],
        limitations=[
            "Unpacked members are extracted only when a sibling "
            "<archive>.unpacked directory exists",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        parser = AsarParser(file, start_offset)
        end_offset = parser.data_offset
        for entry in parser.iter_entries():
            if entry.kind == "file":
                end_offset = max(end_offset, entry.data_offset + entry.size)
        if end_offset > file.size():
            raise InvalidInputFormat("ASAR file data lies beyond the file")
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
