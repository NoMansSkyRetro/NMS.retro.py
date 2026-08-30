from logging import getLogger

from pymhf import Mod
from pymhf.core._internal import BASE_ADDRESS
from pymhf.core._types import DetourTime
from pymhf.core.hooking import hook_manager
from pymhf.core.memutils import map_struct
from pymhf.gui.decorators import no_gui

import nmspy.data.types as nms
from nmspy.common import gameData
from nmspy.data.offsets import global_offset_for
from nmspy.versions import CURRENT_VERSION

logger = getLogger()


@no_gui
class _INTERNAL_LoadSingletons(Mod):
    __author__ = "NoMansSkyRetro"
    __description__ = "Legacy boot: main-loop triggers and the application singleton"
    __version__ = "0.1"

    _booted = False

    @nms.cGcApplication.Update.before
    def _main_loop_before(self, this):
        if not self._booted:
            self._booted = True
            version = CURRENT_VERSION.value if CURRENT_VERSION else "unknown"
            logger.info(f"NMS.retro.py main loop alive (game version {version})")
            # The legacy application is a static global, so no hook gymnastics are
            # needed to find it, unlike the modern game.
            offset = global_offset_for("cGcApplication")
            if offset is not None:
                gameData.GcApplication = map_struct(BASE_ADDRESS + offset, nms.cGcApplication)
        hook_manager.call_custom_callbacks("MAIN_LOOP", DetourTime.BEFORE)

    @nms.cGcApplication.Update.after
    def _main_loop_after(self, this):
        hook_manager.call_custom_callbacks("MAIN_LOOP", DetourTime.AFTER)
