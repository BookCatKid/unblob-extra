"""Generate the Chromium data pack (.pak) integration test fixtures.

The writers below are a straight port of grit's WriteDataPackToString from
Chromium's tools/grit/grit/format/data_pack.py: a versioned header, a table
of {resource_id: u16, offset: u32} index entries with an extra trailing
entry marking the end of the data region, an alias table deduplicating
identical payloads (v5 only), then the concatenated raw resource data.

They were verified by parsing the generated files with the data_pack.py
ReadDataPackFromString algorithm as well as with real production .pak files
shipped inside Electron apps.

Run from the repository root:

    uv run python tests/integration/chromium_pak/gen_pak.py
"""

import struct
from pathlib import Path

OUTPUT = Path(__file__).parent / "__input__"

UTF8 = 1

RES_STRING = b"Sample localized string\x00"
RES_PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(48))
RES_EMPTY = b""


def write_v5(resources: dict, encoding: int = UTF8) -> bytes:
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


def write_v4(resources: dict, encoding: int = UTF8) -> bytes:
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


def main():
    OUTPUT.mkdir(exist_ok=True)
    # ids 20 and 30 carry identical content: grit would alias one of them
    resources = {
        10: RES_STRING,
        20: RES_PNG,
        30: RES_PNG,
        40: RES_EMPTY,
    }
    v5 = write_v5(resources)
    (OUTPUT / "sample.pak").write_bytes(v5)
    (OUTPUT / "sample-v4.pak").write_bytes(write_v4({7: RES_STRING, 42: RES_PNG}))
    (OUTPUT / "sample-embedded.pak").write_bytes(b"\x99" * 64 + v5)


if __name__ == "__main__":
    main()
