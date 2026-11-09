"""Generate the U-Boot uImage integration test fixtures.

Writes a real legacy uImage following U-Boot's image.h layout: a 64-byte
big-endian header (magic, timestamp, size, load/entry addresses, data CRC,
OS/arch/type/compression fields, NUL-padded name) followed by the payload.
ih_hcrc is the CRC32 of the header with that field zeroed; ih_dcrc is the
CRC32 of the payload. Verified against production uImages extracted from
router firmware.

Run from the repository root:

    uv run python tests/integration/uimage/gen_uimage.py
"""

import struct
import zlib
from pathlib import Path

OUTPUT = Path(__file__).parent / "__input__"

MAGIC = 0x27051956
KERNEL_BLOB = b"\x00\x00\xa0\xe1" * 8 + b"fake-zImage-body" + b"\xde\xad" * 64


def write_uimage(
    payload: bytes,
    *,
    os_: int = 5,  # Linux
    arch: int = 2,  # ARM
    type_: int = 2,  # kernel
    comp: int = 1,  # gzip
    name: bytes = b"Linux-3.10.31-test",
) -> bytes:
    dcrc = zlib.crc32(payload)
    header = struct.pack(
        ">7I4B32s",
        MAGIC,
        0,
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
    hcrc = zlib.crc32(header)
    return header[:4] + struct.pack(">I", hcrc) + header[8:] + payload


def write_multi(parts: list[bytes]) -> bytes:
    table = struct.pack(">I", len(parts)) + b"".join(
        struct.pack(">I", len(p)) for p in parts
    )
    return write_uimage(table + b"".join(parts), type_=4, comp=0, name=b"sonos-multi")


def main():
    OUTPUT.mkdir(exist_ok=True)
    sample = write_uimage(KERNEL_BLOB)
    (OUTPUT / "sample.uimage").write_bytes(sample)
    (OUTPUT / "sample-multi.uimage").write_bytes(
        write_multi([b"kernel-part", b"fdt-part", b"ramdisk-part"])
    )
    (OUTPUT / "sample-embedded.uimage").write_bytes(b"\x42" * 96 + sample)


if __name__ == "__main__":
    main()
