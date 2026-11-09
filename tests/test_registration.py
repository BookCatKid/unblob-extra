"""Plugin contract and upstream-migration behavior."""

from pathlib import Path

from unblob.plugins import UnblobPluginManager

import unblob_extra

EXPECTED = {
    "sonos_upd",
    "irobot_apkg",
    "irobot_otps",
    "qt_rcc",
    "installshield_pftw",
    "chromium_pak",
}


def test_handler_names_are_unique():
    names = [handler.NAME for handler in unblob_extra.ALL_HANDLERS]
    assert set(names) == EXPECTED
    assert len(names) == len(set(names))


def test_registration_excludes_upstream_handlers(monkeypatch):
    class AlreadyUpstream:
        NAME = "qt_rcc"

    monkeypatch.setattr(unblob_extra, "BUILTIN_HANDLERS", (AlreadyUpstream,))
    names = {handler.NAME for handler in unblob_extra.unblob_register_handlers()}
    assert names == EXPECTED - {"qt_rcc"}


def test_plugin_loader_discovers_package():
    root = Path(__file__).resolve().parents[1]
    manager = UnblobPluginManager()
    manager.import_path(root)
    names = {handler.NAME for handler in manager.load_handlers_from_plugins()}
    assert names == {
        handler.NAME for handler in unblob_extra.unblob_register_handlers()
    }
