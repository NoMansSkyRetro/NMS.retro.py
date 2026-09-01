from typing import Optional

import ctypes

import nmspy.data.types as nms
from nmspy.data.offsets import global_offset_for, _warn_once
from nmspy.versions import CURRENT_VERSION

import logging

logger = logging.getLogger(__name__)


class GameData:
    """Singletons and accessors shared by all mods.

    Every accessor returns None when the underlying object or field is not mapped in
    the running build, so mods can chain `if x is not None` checks and degrade
    gracefully instead of crashing (see PLAN.md: the framework does the gating).
    """

    GcApplication: nms.cGcApplication = None  # type: ignore
    Simulation: nms.cGcSimulation = None  # type: ignore

    @property
    def simulation(self) -> Optional[nms.cGcSimulation]:
        return self.Simulation

    @property
    def game_state(self):
        """cGcGameState, reached via appdata + 0x194 (1.38 only for now)."""
        if CURRENT_VERSION is None or CURRENT_VERSION.value != "1.38":
            _warn_once("game_state", "game_state chain only mapped for 1.38")
            return None
        appdata = self._appdata_ptr()
        if appdata is None:
            return None
        # cGcGameState is at appdata + 0x194 (confirmed by caller chain analysis)
        gs_addr = appdata + 0x194
        try:
            return nms.cGcGameState.from_address(gs_addr)
        except Exception:
            return None

    @property
    def player(self):
        # Player object chain not yet mapped (needs cGcGameState -> cGcPlayer)
        return None

    @property
    def player_state(self):
        # Player state chain not yet mapped (needs cGcGameState -> cGcPlayerState)
        return None

    @property
    def environment(self) -> Optional[nms.cGcEnvironment]:
        """cGcEnvironment (PlayerEnvironment), reached via appdata + 0x101360 (1.38 only)."""
        if CURRENT_VERSION is None or CURRENT_VERSION.value != "1.38":
            _warn_once("environment", "environment chain only mapped for 1.38")
            return None
        appdata = self._appdata_ptr()
        if appdata is None:
            return None
        # cGcEnvironment is at appdata + 0x101360 (confirmed by ctor + caller analysis)
        env_addr = appdata + 0x101360
        try:
            return nms.cGcEnvironment.from_address(env_addr)
        except Exception:
            return None

    @property
    def player_environment(self) -> Optional[nms.cGcEnvironment]:
        """Alias for environment (Newton uses 'player_environment')."""
        return self.environment

    def _appdata_ptr(self) -> Optional[int]:
        """The cGcApplicationData* pointer for the running build, or None."""
        if self.GcApplication is None:
            return None
        # mpData is at cGcApplication + 0x38 in all builds
        try:
            app_base = ctypes.addressof(self.GcApplication)
            mpdata = ctypes.c_uint64.from_address(app_base + 0x38).value
            return mpdata if mpdata else None
        except Exception:
            return None


gameData = GameData()