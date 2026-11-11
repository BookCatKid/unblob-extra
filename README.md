# unblob-extra

Additional format handlers for [unblob](https://github.com/onekey-sec/unblob), maintained independently of its upstream release schedule. **This is not a fork of unblob** and does not alter the upstream package.

## Supported formats

| Handler | Source contribution | Formats |
| --- | --- | --- |
| `sonos_upd` | [#1704](https://github.com/onekey-sec/unblob/pull/1704) | Sonos UPD firmware sections (encrypted sections identified and preserved, not decrypted) |
| `irobot_apkg` | [#1705](https://github.com/onekey-sec/unblob/pull/1705) | iRobot classic, sequential-table and SigmaStar aPKG OTA containers; exact gzip-member carving, verified MD5 and decoded SKU metadata |
| `irobot_otps` | [#1705](https://github.com/onekey-sec/unblob/pull/1705) | iRobot Qualcomm Otps component packages |
| `irobot_compact_fat16` | local | Compact Qualcomm FAT16 images from iRobot Otps payloads, verified allocation-table recovery of omitted free-space sectors |
| `qt_rcc` | [#1706](https://github.com/onekey-sec/unblob/pull/1706) | Qt RCC v1–v3 resources, raw/zlib/zstd |
| `installshield_pftw` | [#1707](https://github.com/onekey-sec/unblob/pull/1707) | InstallShield PackageForTheWeb (classic and stream variants) |

The handler sources come from the linked upstream PRs, including their parsing and extraction logic. The package adds only registration, tests and packaging around them. A handler is registered **only while unblob lacks a built-in handler with the same name**, allowing support to graduate upstream without duplicate registration.

## Run as an installed package

Requires Python 3.10+ and a compatible unblob installation.

```bash
python -m pip install 'git+https://github.com/BookCatKid/unblob-extra.git'
unblob firmware.bin
```

Installation registers the handlers automatically using unblob's `unblob_v1` Python entry-point mechanism.

For SigmaStar OTA packages, `irobot_apkg` keeps the gzip member as
`SStarOta.bin.gz`, preserves every byte of the post-gzip region as
`SStarOta.bin.metadata.bin`, and (when the observed 976-byte layout validates)
creates `SStarOta.bin.metadata.json` with the gzip MD5 and embedded SKU
identifier. The 976-byte structure contains MD5 ASCII at offset 0 and a
NUL-terminated SKU at offset `0x200`; unsupported layouts are preserved
without guessed fields. Standard unblob recursion then extracts the gzip
member and embedded ext4/SquashFS images. Note that ext4 extraction requires
`debugfs`, and unblob's built-in SquashFS handler requires `sasquatch` (the
presence of `unsquashfs` alone is insufficient).

## Run directly from the checkout

If you already have unblob installed and do not want to install the plugin package:

```bash
git clone https://github.com/BookCatKid/unblob-extra.git
unblob -P ./unblob-extra firmware.bin
```

`-P` and automatic entry-point registration are alternative loading modes. Use one mode for a given invocation, not both.

## Development and tests

```bash
python -m pip install -e '.[test]'
python -m pytest -q
ruff check unblob_extra tests
ruff format --check unblob_extra tests
```

`tests/test_*.py` preserves the original upstream PR unit tests; `tests/integration/` contains the original PR binary fixtures and expected extracted data. Tests include the plugin registration contract and compatibility with upstream merges.

## Contribution workflow

Each handler should be justified by reversing the binary format and validating its structure against real binaries, not simply by trying inputs until extraction appears to work. Include evidence of header fields, section bounds, nested formats and integrity checks; run malformed-input and byte-for-byte regression tests. When an upstream PR merges, the handler remains in this collection only until the next maintenance cleanup; registration already suppresses the duplicate.

## Scope and provenance

- Sonos UPD format research: https://github.com/BookCatKid/sonos-firmware-archive
- iRobot aPKG/Otps format research: https://github.com/BookCatKid/irobot-firmware-archive
- Qt format reference: [qtbase resource implementation](https://codebrowser.dev/qt5/qtbase/src/corelib/io/qresource.cpp.html)
- InstallShield PftW format reference: [ISx](https://github.com/lifenjoiner/ISx)

### Compact FAT16 firmware partitions

Some Qualcomm `NON-HLOS.bin` files inside iRobot Otps archives store FAT16
filesystems with only their allocated clusters present. For example, the
Wichita 1.0.0 image contains 19,105,280 bytes, while its boot sector declares
67,108,864 bytes. The FAT16 allocation table proves the last allocated
cluster ends at exactly the physical file boundary; the missing 48 MB is
unallocated trailing slack, **not** missing firmware.

Unblob's standard FAT handler can locate this compact image but its `7z`
extractor reports an unexpected end. The `irobot_compact_fat16` handler
preempts the generic FAT detection for the verified `MSDOS5.0` / 512-byte-sector
FAT16 layout, validates the allocation table, and creates a temporary sparse
copy with zero-filled unused sectors before delegating to `7z`. Both the
original input and its exact carved bytes are preserved. It refuses images
whose final allocated cluster is not fully present, and otherwise lets the
built-in FAT handler process normal full-length images. Requires `7z`.

The handler was validated on an archived signed Wichita 1.0.0 firmware image;
no proprietary firmware bytes are shipped as tests or fixtures.

The plugin does not bundle firmware encryption keys, downloaded firmware images, or device-specific extraction programs.

## License

MIT. See [LICENSE](LICENSE).
