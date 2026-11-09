"""U-Boot legacy uImage firmware images.

The classic U-Boot image format (mkimage -A/-O/-T/-C), still stamped on
kernels, ramdisks and scripts inside router, camera and NAS firmware:

    image_header, 64 bytes, all big-endian:
        u32 ih_magic   // 0x27051956
        u32 ih_hcrc    // CRC32 of the header with this field zeroed
        u32 ih_time    // build timestamp
        u32 ih_size    // payload size (excludes this header)
        u32 ih_load    // load address
        u32 ih_ep      // entry point
        u32 ih_dcrc    // CRC32 of the payload
        u8  ih_os      // 0..~30 (5 = Linux)
        u8  ih_arch    // 0..~30 (2 = ARM, 7 = PPC)
        u8  ih_type    // 0..~40 (2 kernel, 3 ramdisk, 4 multi, 7 filesystem)
        u8  ih_comp    // 0 none, 1 gzip, 2 bzip2, 3 lzma, 4 lzo, 5 lz4, 6 zstd
        u8  ih_name[32]

    payload, ih_size bytes

Two CRC32 fields over independent ranges make the signature effectively
self-verifying. Type 4 ("multi") payloads are themselves a table of
u32 count + count u32 sizes followed by concatenated images.
"""

from __future__ import annotations

import io
import zlib
from pathlib import Path
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
    typedef struct uimage_header {
        uint32  ih_magic;
        uint32  ih_hcrc;
        uint32  ih_time;
        uint32  ih_size;
        uint32  ih_load;
        uint32  ih_ep;
        uint32  ih_dcrc;
        uint8   ih_os;
        uint8   ih_arch;
        uint8   ih_type;
        uint8   ih_comp;
        char    ih_name[32];
    } uimage_header_t;
"""
UIMAGE_HEADER = "uimage_header_t"
UIMAGE_HEADER_SIZE = 0x40

UIMAGE_MAGIC = 0x27051956

# generous bounds; the enum fields keep growing with new U-Boot releases
MAX_OS = 0x40
MAX_ARCH = 0x40
MAX_TYPE = 0x40
MAX_COMP = 7

TYPE_MULTI = 4

COMP_SUFFIX = {
    0: "",
    1: ".gz",
    2: ".bz2",
    3: ".lzma",
    4: ".lzo",
    5: ".lz4",
    6: ".zst",
}

MAX_MULTI_MEMBERS = 0x1000


class _Member:
    __slots__ = ("data_offset", "name", "size")

    def __init__(self, name: str, data_offset: int, size: int):
        self.name = name
        self.data_offset = data_offset
        self.size = size


class UImageParser:
    """Parse and validate a U-Boot legacy image header."""

    def __init__(self, file: File, start_offset: int = 0):
        self.file = file
        self.start_offset = start_offset
        self.file.seek(start_offset, io.SEEK_SET)
        self.struct_parser = StructParser(C_DEFINITIONS)
        self.header = self.struct_parser.parse(UIMAGE_HEADER, file, Endian.BIG)
        self._validate()
        self.data_offset = start_offset + UIMAGE_HEADER_SIZE

    def _validate(self):
        header = self.header
        if header.ih_magic != UIMAGE_MAGIC:
            raise InvalidInputFormat("no uImage magic")
        raw = self.file[self.start_offset : self.start_offset + UIMAGE_HEADER_SIZE]
        hcrc = zlib.crc32(bytes(raw[:4]) + b"\x00" * 4 + bytes(raw[8:]))
        if hcrc != header.ih_hcrc:
            raise InvalidInputFormat("uImage header CRC mismatch")
        if header.ih_size == 0:
            raise InvalidInputFormat("uImage with no payload")
        if self.start_offset + UIMAGE_HEADER_SIZE + header.ih_size > self.file.size():
            raise InvalidInputFormat("uImage payload lies beyond the file")
        if (
            header.ih_os > MAX_OS
            or header.ih_arch > MAX_ARCH
            or header.ih_type > MAX_TYPE
            or header.ih_comp > MAX_COMP
        ):
            raise InvalidInputFormat("uImage field out of range")
        # the data CRC is the second line of defence against false positives;
        # computing it here also means a corrupt image is rejected at chunk
        # calculation rather than silently extracting garbage
        dcrc = 0
        data_start = self.start_offset + UIMAGE_HEADER_SIZE
        for chunk in iterate_file(self.file, data_start, header.ih_size):
            dcrc = zlib.crc32(chunk, dcrc)
        if dcrc != header.ih_dcrc:
            raise InvalidInputFormat("uImage data CRC mismatch")

    @property
    def image_name(self) -> str:
        raw = bytes(self.header.ih_name).split(b"\x00", 1)[0]
        name = raw.decode("utf-8", errors="replace").strip()
        # keep it a simple file name
        name = name.replace("/", "_").replace("\\", "_").lstrip(".")
        return name or "uImage"

    def iter_members(self) -> Iterable[_Member]:
        if self.header.ih_type != TYPE_MULTI:
            suffix = COMP_SUFFIX.get(self.header.ih_comp, "")
            yield _Member(
                self.image_name + suffix, self.data_offset, self.header.ih_size
            )
            return
        yield from self._iter_multi()

    def _iter_multi(self) -> Iterable[_Member]:
        # multi payloads: u32 count, count u32 sizes, concatenated images
        file = self.file
        base = self.data_offset
        end = base + self.header.ih_size
        count = int.from_bytes(file[base : base + 4], "big")
        if not 0 < count <= MAX_MULTI_MEMBERS:
            raise InvalidInputFormat(f"invalid uImage multi count {count}")
        sizes_end = base + 4 + count * 4
        if sizes_end > end:
            raise InvalidInputFormat("uImage multi table lies beyond the payload")
        sizes = [
            int.from_bytes(file[base + 4 + i * 4 : base + 8 + i * 4], "big")
            for i in range(count)
        ]
        if sum(sizes) > end - sizes_end:
            raise InvalidInputFormat("uImage multi members lie beyond the payload")
        pos = sizes_end
        name = self.image_name
        for i, size in enumerate(sizes):
            yield _Member(f"{name}.{i}", pos, size)
            pos += size


class UImageExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            parser = UImageParser(file)
            for member in parser.iter_members():
                try:
                    fs.carve(
                        Path(member.name),
                        file,
                        member.data_offset,
                        member.size,
                    )
                except OSError as e:
                    fs.record_problem(
                        ExtractionProblem(
                            problem=f"Failed to extract uImage member: {e}",
                            resolution="Skipped.",
                            path=member.name,
                        )
                    )
        return ExtractResult(reports=fs.problems)


class UImageHandler(Handler):
    NAME = "uimage"
    PATTERNS = [
        # uImage magic
        HexString("27 05 19 56"),
    ]
    EXTRACTOR = UImageExtractor()
    DOC = HandlerDoc(
        name="U-Boot legacy uImage",
        description=(
            "The classic mkimage/U-Boot firmware image: a 64-byte big-endian "
            "header with magic, timestamps, load/entry addresses, "
            "OS/arch/type/compression enum fields, a 32-byte name, and two "
            "CRC32s - one over the header, one over the payload - followed "
            "by the image data. Type 4 'multi' payloads carry a table of "
            "member sizes and are split during extraction."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="DENX (U-Boot)",
        references=[
            Reference(
                title="U-Boot image.h format definitions",
                url=(
                    "https://github.com/u-boot/u-boot/blob/master/tools/include/image.h"
                ),
            ),
        ],
        limitations=[
            "Compressed payloads are carved, not decompressed; the "
            "compression type is encoded in the extracted file suffix",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        parser = UImageParser(file, start_offset)
        return ValidChunk(
            start_offset=start_offset,
            end_offset=parser.data_offset + parser.header.ih_size,
        )
