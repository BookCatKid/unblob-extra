"""Chromium data pack (.pak) resource archives.

GRIT (Chromium's resource compiler) packs translations, images and other
app resources into .pak files shipped beside every Chromium/Electron binary.
The format is a flat resource table; resources have numeric IDs, not names:

    v5 header, 12 bytes, little-endian:
        u32 version (=5)
        u8  encoding (0 binary, 1 utf8, 2 utf16)
        u8  pad[3]
        u16 resource_count
        u16 alias_count

    v4 header, 9 bytes (older, no aliases):
        u32 version (=4)
        u32 resource_count
        u8  encoding

    index: resource_count + 1 entries of {u16 resource_id, u32 offset};
           the extra trailing entry's offset marks the end of the data
           region, so a resource's length is next_offset - offset
    aliases (v5 only): alias_count entries of {u16 resource_id,
           u16 entry_index}; an alias shares the data of the index
           entry it points at
    data: the concatenated resource payloads

Offsets are absolute within the pack, monotonically non-decreasing, and the
first entry's offset is exactly the end of the tables, which gives the
format a fully deterministic extent.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING

from structlog import get_logger
from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
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
    typedef struct pak_header_v5 {
        uint32  version;         // 5
        uint8   encoding;        // 0 binary, 1 utf8, 2 utf16
        uint8   pad[3];
        uint16  resource_count;
        uint16  alias_count;
    } pak_header_v5_t;

    typedef struct pak_header_v4 {
        uint32  version;         // 4
        uint32  resource_count;
        uint8   encoding;
    } pak_header_v4_t;

    typedef struct pak_index_entry {
        uint16  resource_id;
        uint32  offset;          // absolute within the pack
    } pak_index_entry_t;

    typedef struct pak_alias_entry {
        uint16  resource_id;
        uint16  entry_index;     // index into the entry table
    } pak_alias_entry_t;
"""
PAK_HEADER_V5 = "pak_header_v5_t"
PAK_HEADER_V4 = "pak_header_v4_t"
PAK_INDEX_ENTRY = "pak_index_entry_t"
PAK_ALIAS_ENTRY = "pak_alias_entry_t"

PAK_HEADER_V5_SIZE = 0xC
PAK_HEADER_V4_SIZE = 0x9
PAK_INDEX_ENTRY_SIZE = 0x6
PAK_ALIAS_ENTRY_SIZE = 0x4

MAX_ENCODING = 2  # BINARY=0, UTF8=1, UTF16=2


class _Resource:
    __slots__ = ("data_end", "data_offset", "resource_id")

    def __init__(self, resource_id: int, data_offset: int, data_end: int):
        self.resource_id = resource_id
        self.data_offset = data_offset
        self.data_end = data_end


class PakParser:
    """Iterate the resources of a Chromium data pack."""

    def __init__(self, file: File, start_offset: int = 0):
        self.file = file
        self.start_offset = start_offset
        self.struct_parser = StructParser(C_DEFINITIONS)
        self.file.seek(start_offset, io.SEEK_SET)
        version = int.from_bytes(file[start_offset : start_offset + 4], "little")
        if version == 5:
            header = self.struct_parser.parse(PAK_HEADER_V5, file, Endian.LITTLE)
            self.encoding = header.encoding
            self.resource_count = header.resource_count
            self.alias_count = header.alias_count
            self.header_size = PAK_HEADER_V5_SIZE
        elif version == 4:
            header = self.struct_parser.parse(PAK_HEADER_V4, file, Endian.LITTLE)
            self.encoding = header.encoding
            self.resource_count = header.resource_count
            self.alias_count = 0
            self.header_size = PAK_HEADER_V4_SIZE
        else:
            raise InvalidInputFormat(f"unsupported PAK version {version}")
        self.version = version
        self._validate_header()
        self.entries = self._read_index()
        self.aliases = self._read_aliases()

    def _validate_header(self):
        if self.encoding > MAX_ENCODING:
            raise InvalidInputFormat(f"invalid PAK encoding {self.encoding}")
        self.index_size = (self.resource_count + 1) * PAK_INDEX_ENTRY_SIZE
        self.alias_size = self.alias_count * PAK_ALIAS_ENTRY_SIZE
        self.data_offset = self.header_size + self.index_size + self.alias_size
        if self.start_offset + self.data_offset > self.file.size():
            raise InvalidInputFormat("PAK tables lie beyond the file")

    def _read_index(self) -> list:
        entries = []
        prev_offset = None
        for _ in range(self.resource_count + 1):
            entry = self.struct_parser.parse(PAK_INDEX_ENTRY, self.file, Endian.LITTLE)
            if prev_offset is not None and entry.offset < prev_offset:
                raise InvalidInputFormat("PAK index offsets are not ordered")
            prev_offset = entry.offset
            entries.append(entry)
        first, last = entries[0], entries[-1]
        # the writer emits the first resource exactly at the data start
        if first.offset != self.data_offset:
            raise InvalidInputFormat("PAK data does not start after the tables")
        if self.start_offset + last.offset > self.file.size():
            raise InvalidInputFormat("PAK data lies beyond the file")
        ids = [entry.resource_id for entry in entries[:-1]]
        if ids != sorted(set(ids)):
            raise InvalidInputFormat("PAK resource IDs are not sorted and unique")
        return entries

    def _read_aliases(self) -> list:
        real_ids = {entry.resource_id for entry in self.entries[:-1]}
        aliases = []
        for _ in range(self.alias_count):
            alias = self.struct_parser.parse(PAK_ALIAS_ENTRY, self.file, Endian.LITTLE)
            if alias.entry_index >= self.resource_count:
                raise InvalidInputFormat("PAK alias points outside the index")
            if alias.resource_id in real_ids:
                raise InvalidInputFormat("PAK alias shadows a real resource")
            aliases.append(alias)
        return aliases

    def iter_resources(self) -> Iterable[_Resource]:
        for i in range(self.resource_count):
            entry, following = self.entries[i], self.entries[i + 1]
            yield _Resource(
                entry.resource_id,
                self.start_offset + entry.offset,
                self.start_offset + following.offset,
            )
        for alias in self.aliases:
            target, following = (
                self.entries[alias.entry_index],
                self.entries[alias.entry_index + 1],
            )
            yield _Resource(
                alias.resource_id,
                self.start_offset + target.offset,
                self.start_offset + following.offset,
            )


class PakExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            parser = PakParser(file)
            for resource in parser.iter_resources():
                try:
                    fs.carve(
                        Path(str(resource.resource_id)),
                        file,
                        resource.data_offset,
                        resource.data_end - resource.data_offset,
                    )
                except OSError as e:
                    fs.record_problem(
                        ExtractionProblem(
                            problem=f"Failed to extract PAK resource: {e}",
                            resolution="Skipped.",
                            path=str(resource.resource_id),
                        )
                    )
        return ExtractResult(reports=fs.problems)


class ChromiumPakHandler(Handler):
    NAME = "chromium_pak"
    PATTERNS = [
        # v5: version, encoding (0-2), three padding bytes
        HexString("05 00 00 00 ( 00 | 01 | 02 ) [3]"),
        # v4: version, u32 resource_count, encoding (0-2)
        HexString("04 00 00 00 [4] ( 00 | 01 | 02 )"),
    ]
    EXTRACTOR = PakExtractor()
    DOC = HandlerDoc(
        name="Chromium data pack",
        description=(
            "GRIT resource packs shipped with Chromium and Electron apps: a "
            "version/encoding header, a table of resource ID to offset "
            "pairs with a trailing end-of-data entry, an alias table "
            "deduplicating repeated payloads (v5), then the raw resource "
            "data. Resources carry numeric IDs rather than file names."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="Chromium project",
        references=[
            Reference(
                title="Chromium grit data_pack.py format implementation",
                url=(
                    "https://chromium.googlesource.com/chromium/src/tools/grit/"
                    "+/refs/heads/main/grit/format/data_pack.py"
                ),
            ),
        ],
        limitations=[
            "Resource names are not stored; extracted files are named by "
            "their numeric resource ID",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        parser = PakParser(file, start_offset)
        # the trailing index entry's offset is the end of the data region
        end_offset = start_offset + parser.entries[-1].offset
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
