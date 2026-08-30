import ctypes
from logging import getLogger

from pymhf import Mod
from pymhf.core._internal import BASE_ADDRESS
from pymhf.core._types import DetourTime
from pymhf.core.hooking import hook_manager, one_shot
from pymhf.core.memutils import map_struct
from pymhf.gui.decorators import no_gui

import nmspy.data.types as nms
from nmspy.common import gameData
from nmspy.data.enums import StateEnum
from nmspy.data.offsets import global_offset_for
from nmspy.versions import CURRENT_VERSION

logger = getLogger()

# 1.09.1 has no ModeSelector state (game modes arrived with Foundation), so "fully
# booted" there means entering the simulation directly.
_BOOTED_STATES = {
    StateEnum.ApplicationGameModeSelectorState.value,
    StateEnum.ApplicationSimulationState.value,
}


@no_gui
class _INTERNAL_LoadSingletons(Mod):
    __author__ = "NoMansSkyRetro"
    __description__ = "Legacy boot: singleton mapping, main-loop and state triggers"
    __version__ = "0.1"

    _main_loop_seen = False
    _booted = False

    @nms.cGcApplication.Update.before
    def _main_loop_before(self, this):
        if not self._main_loop_seen:
            self._main_loop_seen = True
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

    @one_shot
    @nms.cGcSimulation.Construct.after
    def _capture_simulation(self, this):
        logger.debug(f"cGcSimulation found at 0x{this:X}")
        gameData.Simulation = map_struct(this, nms.cGcSimulation)

    @nms.cTkFSM.StateChange.after
    def _state_change(self, this, lNewStateID, lpUserData, lbForceRestart):
        new_state = ctypes.string_at(lNewStateID, 0x10).split(b"\0", 1)[0].decode()
        logger.info(f"New State: {new_state}")
        if not self._booted and new_state in _BOOTED_STATES:
            self._booted = True
            hook_manager.call_custom_callbacks("MODESELECTOR", DetourTime.AFTER)
            hook_manager.call_custom_callbacks("MODESELECTOR", DetourTime.NONE)
        hook_manager.call_custom_callbacks(new_state, DetourTime.AFTER)
        hook_manager.call_custom_callbacks(new_state, DetourTime.NONE)
