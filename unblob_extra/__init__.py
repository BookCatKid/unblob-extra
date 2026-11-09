"""External firmware and resource format handlers for unblob.

Available via the ``unblob_v1`` entry point or ``unblob -P /path/to/repo``.
Handlers merged into upstream unblob are automatically excluded by name.
"""

from unblob.handlers import BUILTIN_HANDLERS
from unblob.models import Handler
from unblob.plugins import hookimpl

from .handlers.installshield_pftw import InstallShieldPftwHandler
from .handlers.irobot.apkg import IRobotApkgHandler
from .handlers.irobot.otps import IRobotOtpsHandler
from .handlers.qt_rcc import QtRccHandler
from .handlers.sonos_upd import SonosUPDHandler

ALL_HANDLERS: tuple[type[Handler], ...] = (
    SonosUPDHandler,
    IRobotApkgHandler,
    IRobotOtpsHandler,
    QtRccHandler,
    InstallShieldPftwHandler,
)


@hookimpl
def unblob_register_handlers() -> list[type[Handler]]:
    """Register only handlers not already available in upstream unblob."""
    upstream_names = {handler.NAME for handler in BUILTIN_HANDLERS}
    return [handler for handler in ALL_HANDLERS if handler.NAME not in upstream_names]
