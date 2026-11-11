"""Compact FAT16 images shipped inside Qualcomm NON-HLOS firmware.

The verified iRobot Wichita 1.0.0 NON-HLOS.bin declares 131072 sectors of
512 bytes (64 MiB logical size), but physically stores only the first
19,105,280 bytes. Its last allocated FAT16 cluster is 1165, whose end is
*exactly* byte 19,105,280. All omitted sectors are unallocated slack.

The builtin FAT handler already detects the actual chunk boundary, but its
7z extractor rejects an image shorter than the BPB's declared total size.
For this proven layout only, recreate the omitted slack as sparse zero-filled
space, then delegate to the standard 7z FAT extractor. The carved original
file is never modified. Truncation inside allocated data is not repaired.
"""

import shutil
import tempfile
from pathlib import Path

from pyfatfs._exceptions import PyFATException
from unblob.extractors.command import Command
from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.filesystem.fat import PyFatNoClose, get_max_offset
from unblob.models import (
    Extractor,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    ValidChunk,
)

_MAX_LOGICAL_FAT16_SIZE = 1 << 30


def _logical_size(file, offset: int) -> int:
    """Read the FAT16 BPB, rejecting layouts outside this narrow handler."""
    file.seek(offset)
    boot = file.read(512)
    if len(boot) != 512 or boot[510:512] != b"\x55\xaa":
        raise InvalidInputFormat("Missing FAT boot-sector terminator")
    if boot[3:11] != b"MSDOS5.0" or boot[11:13] != b"\x00\x02":
        raise InvalidInputFormat("Not the recognized Qualcomm FAT16 boot sector")
    if boot[54:62] != b"FAT16   ":
        raise InvalidInputFormat("Not FAT16")
    sectors_per_cluster = boot[13]
    reserved = int.from_bytes(boot[14:16], "little")
    fats = boot[16]
    root_entries = int.from_bytes(boot[17:19], "little")
    fat_sectors = int.from_bytes(boot[22:24], "little")
    total = int.from_bytes(boot[19:21], "little") or int.from_bytes(
        boot[32:36], "little"
    )
    if (
        sectors_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128)
        or not reserved
        or fats not in (1, 2)
        or not root_entries
        or not fat_sectors
        or total < 1
    ):
        raise InvalidInputFormat("Invalid FAT16 geometry")
    root_sectors = (root_entries * 32 + 511) // 512
    data_sectors = total - (reserved + fats * fat_sectors + root_sectors)
    cluster_count = data_sectors // sectors_per_cluster
    if not 4085 <= cluster_count < 65525:
        raise InvalidInputFormat("FAT cluster count is not FAT16")
    logical_size = total * 512
    if logical_size > _MAX_LOGICAL_FAT16_SIZE:
        raise InvalidInputFormat("Compact FAT16 image exceeds safe maximum")
    return logical_size


class CompactFat16Extractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        # Recheck the allocation table, even for direct extractor calls, so
        # truncation inside an allocated cluster is never concealed by padding.
        with File.from_path(inpath) as source:
            chunk = CompactFat16Handler().calculate_chunk(source, 0)
            if chunk is None or chunk.end_offset != inpath.stat().st_size:
                raise InvalidInputFormat("Not a complete compact FAT16 image")
            logical_size = _logical_size(source, 0)
        # A sparse file occupies just the physically stored bytes on disk;
        # expanding to BPB logical length allocates no fictitious data blocks.
        # The original carved image remains unchanged and retained by unblob.
        with tempfile.TemporaryDirectory(prefix="unblob-fat16-", dir=outdir) as tmp:
            padded = Path(tmp) / "complete-fat16.img"
            with inpath.open("rb") as source, padded.open("wb") as target:
                shutil.copyfileobj(source, target, length=1 << 20)
                target.truncate(logical_size)
            return Command("7z", "x", "-y", "{inpath}", "-o{outdir}").extract(
                padded, outdir
            )

    def get_dependencies(self) -> list[str]:
        return ["7z"]


class CompactFat16Handler(Handler):
    NAME = "irobot_compact_fat16"
    # Earlier match than upstream FAT's 512-byte signature, but much more
    # restrictive calculate_chunk: only validated MSDOS5.0 FAT16 images that
    # end precisely at the final allocated data cluster are accepted.
    PATTERNS = [HexString("( EB | E9 ) [2] 4D 53 44 4F 53 35 2E 30 00 02")]
    EXTRACTOR = CompactFat16Extractor()
    DOC = HandlerDoc(
        name="iRobot compact FAT16",
        description=(
            "Qualcomm NON-HLOS FAT16 firmware images that omit unused trailing "
            "sectors. The allocation table must prove all allocated clusters "
            "are physically present; omitted free space is reconstructed "
            "sparsely for the standard 7z extractor."
        ),
        handler_type=HandlerType.FILESYSTEM,
        vendor="iRobot / Qualcomm",
        references=[
            Reference(
                title="iRobot firmware archive",
                url="https://github.com/BookCatKid/irobot-firmware-archive",
            )
        ],
        limitations=["Only the observed MSDOS5.0 / 512-byte-sector FAT16 layout"],
    )

    def calculate_chunk(self, file, start_offset: int) -> ValidChunk | None:
        logical_size = _logical_size(file, start_offset)
        available = file.size() - start_offset
        if available >= logical_size:
            # Full-sized FAT images belong to the upstream FAT handler.
            return None
        fs = PyFatNoClose(offset=start_offset)
        try:
            fs.set_fp(file)
            max_used = get_max_offset(fs)
        except (PyFATException, ValueError, IndexError) as exc:
            raise InvalidInputFormat("Invalid FAT16 allocation table") from exc
        if max_used != available or max_used <= 0:
            # An image cut within an allocated cluster has missing data.
            raise InvalidInputFormat("Compact FAT16 cuts through allocated data")
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + max_used)
