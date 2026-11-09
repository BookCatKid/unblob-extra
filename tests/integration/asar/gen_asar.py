"""Generate the ASAR integration test fixtures.

The writer below emits a real Electron ASAR archive: Chromium pickle framing
(a u32 outer pickle size, a u32 header size, then the header pickle holding
the length-prefixed JSON index padded to a 4-byte boundary) followed by the
concatenated raw file payloads.

It was verified bidirectionally: archives written here are read back
byte-exact by the independent `asar` PyPI package (black-06/asar-py), and
archives written by that package - as well as production app.asar files
extracted from Electron apps - are parsed and extracted correctly by the
handler under test.

Run from the repository root:

    uv run python tests/integration/asar/gen_asar.py
"""

import hashlib
import json
import struct
from pathlib import Path

OUTPUT = Path(__file__).parent / "__input__"

MAIN_JS = b"console.log('hello from asar');\n"
DATA_BIN = bytes(range(256)) * 4
CLAUDE_MD = b"# fixture docs\n"
TOOL_SH = b"#!/bin/sh\necho tool\n"


def insert(tree: dict, path: str, node: dict):
    parts = path.split("/")
    d = tree
    for part in parts[:-1]:
        d = d.setdefault(part, {"files": {}})["files"]
    d[parts[-1]] = node


def build_index() -> tuple[dict, bytes]:
    tree, data = {}, bytearray()

    def add_file(path: str, content: bytes, **extra):
        node = {"size": len(content), "offset": str(len(data)), **extra}
        data.extend(content)
        insert(tree, path, node)

    add_file(
        "app/main.js",
        MAIN_JS,
        integrity={
            "algorithm": "SHA256",
            "hash": hashlib.sha256(MAIN_JS).hexdigest(),
            "blockSize": 4194304,
            "blocks": [hashlib.sha256(MAIN_JS).hexdigest()],
        },
    )
    add_file("app/lib/data.bin", DATA_BIN)
    add_file("bin/tool", TOOL_SH, executable=True)
    add_file("docs/CLAUDE.md", CLAUDE_MD)
    # link targets are relative to the archive root
    insert(tree, "docs/AGENTS.md", {"link": "docs/CLAUDE.md"})
    # payload lives in a sibling .unpacked dir, absent for this fixture
    insert(tree, "native.node", {"size": 512, "unpacked": True})
    return tree, bytes(data)


def write_asar(path: Path, tree: dict, data: bytes):
    index = json.dumps({"files": tree}, separators=(",", ":")).encode()
    payload = struct.pack("<I", len(index)) + index
    payload += b"\x00" * (-len(payload) % 4)
    blob = struct.pack("<III", 4, 4 + len(payload), len(payload)) + payload + data
    path.write_bytes(blob)


def main():
    OUTPUT.mkdir(exist_ok=True)
    tree, data = build_index()
    write_asar(OUTPUT / "sample.asar", tree, data)
    embedded = b"\xde\xad\xbe\xef" * 16 + (OUTPUT / "sample.asar").read_bytes()
    (OUTPUT / "sample-embedded.asar").write_bytes(embedded)


if __name__ == "__main__":
    main()
