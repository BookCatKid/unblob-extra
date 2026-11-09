# unblob-extra

Additional format handlers for [unblob](https://github.com/onekey-sec/unblob), maintained independently of its upstream release schedule. **This is not a fork of unblob** and does not alter the upstream package.

## Supported formats

| Handler | Source contribution | Formats |
| --- | --- | --- |
| `sonos_upd` | [#1704](https://github.com/onekey-sec/unblob/pull/1704) | Sonos UPD firmware sections (encrypted sections identified and preserved, not decrypted) |
| `irobot_apkg` | [#1705](https://github.com/onekey-sec/unblob/pull/1705) | iRobot classic, sequential-table and SigmaStar aPKG OTA containers |
| `irobot_otps` | [#1705](https://github.com/onekey-sec/unblob/pull/1705) | iRobot Qualcomm Otps component packages |
| `qt_rcc` | [#1706](https://github.com/onekey-sec/unblob/pull/1706) | Qt RCC v1–v3 resources, raw/zlib/zstd |
| `installshield_pftw` | [#1707](https://github.com/onekey-sec/unblob/pull/1707) | InstallShield PackageForTheWeb (classic and stream variants) |
| `uimage` | local | U-Boot legacy uImage (kernel/ramdisk/multi payloads, dual CRC32 validation) |

The handler sources come from the linked upstream PRs, including their parsing and extraction logic. The package adds only registration, tests and packaging around them. A handler is registered **only while unblob lacks a built-in handler with the same name**, allowing support to graduate upstream without duplicate registration. Handlers marked "local" were written for this package and have no upstream contribution yet.

## Run as an installed package

Requires Python 3.10+ and a compatible unblob installation.

```bash
python -m pip install 'git+https://github.com/BookCatKid/unblob-extra.git'
unblob firmware.bin
```

Installation registers the handlers automatically using unblob's `unblob_v1` Python entry-point mechanism.

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

The plugin does not bundle firmware encryption keys, downloaded firmware images, or device-specific extraction programs.

## License

MIT. See [LICENSE](LICENSE).
