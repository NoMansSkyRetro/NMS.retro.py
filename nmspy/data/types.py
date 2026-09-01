"""Legacy game types and hooked functions.

Rebuilt from scratch for the four legacy builds this fork targets. The modern (4.x)
definitions this file replaced live in upstream NMS.py and in git history.

Design: this module declares the FULL API surface mods use (classes, hooks, fields),
so a mod written against nmspy imports and loads unmodified on every build. Whether
each piece actually works on the running build is data-driven:

- Hooks resolve to per-build static addresses from ``offsets.json`` (derived with the
  scripts in ``tools/legacy_re/``). A hook with no address for the running build is
  disabled: detours never fire (warning at load), and calling the game function
  returns None with a one-time warning.
- Struct fields are declared per-version via ``_vfields_``; a field not mapped in the
  running build reads as None with a one-time warning.

Pointer arguments are annotated as raw ``c_uint64`` addresses until each struct's
legacy layout is verified; see tools/legacy_re/findings.md for what is known so far.
"""

from ctypes import c_bool, c_char, c_float, c_int32, c_uint64
from logging import getLogger

from pymhf.core.hooking import Structure

from nmspy.data.basic_types import TkHandle, Vector3f

# The auto-generated full upstream hook surface (see tools/legacy_re/
# generate_hook_stubs.py). Everything it defines is importable from this module;
# the hand-written classes below inherit from it and refine what they need.
from nmspy.data.generated_hooks import *  # noqa: F401,F403
import nmspy.data.generated_hooks as gen
from nmspy.data.offsets import _warn_once, legacy_hook, versioned_struct

logger = getLogger(__name__)


@versioned_struct
class cTkFSM(gen.cTkFSM, Structure):
    # Layout notes in tools/legacy_re/findings.md; fields added as they are verified.
    _vfields_ = {
        # The active cTkFSMState*.
        "mpCurrState": (c_uint64, 0x10),
        # The requested next state ID; FSM_NoState when no transition is pending.
        "macPendingStateID": (c_char * 0x10, 0x18),
    }

    @legacy_hook("cTkFSM::Update")
    def Update(self, this: c_uint64, lfTimestep: c_float): ...

    @legacy_hook("cTkFSM::StateChange")
    def StateChange(
        self,
        this: c_uint64,
        lNewStateID: c_uint64,
        lpUserData: c_uint64,
        lbForceRestart: c_bool,
    ):
        """The transition performer: exits the current state and enters the new one.

        Every state transition passes through here exactly once (unlike
        cTkFSMState::StateChange, which is inlined at most request sites), so this is
        the hook for state-change notifications. ``lNewStateID`` points at the new
        state's cTkFixedString<0x10> ID.
        """
        ...


class cTkFSMState(gen.cTkFSMState, Structure):
    @legacy_hook("cTkFSMState::StateChange")
    def StateChange(
        self,
        this: c_uint64,
        lNewStateID: c_uint64,
        lpUserData: c_uint64,
        lbForceRestart: c_bool,
    ):
        """Request a transition on the parent FSM (this+0x18).

        1.09.1/1.13 builds only take (this, lNewStateID); the trailing arguments are
        register garbage there and must be ignored.
        """
        ...


@versioned_struct
class cGcApplication(gen.cGcApplication, cTkFSM):
    """The static application singleton (a cTkFSM whose states are the App* states)."""

    # The app is a static singleton (base = the value passed to cTkFSM::Construct/Update in
    # cGcApplication::Construct/Update: 1.09.1 &DAT_14160BA50, 1.13 &DAT_1417F6C80,
    # 1.24 &DAT_141A433F0, 1.38 &DAT_142033690); mpData (cGcApplicationData*) sits at base+0x38
    # in every build and the big subsystems live behind it, so modern deep offsets do not map.
    _vfields_ = {\r\n        "mpData": (c_uint64, 0x38),  # cGcApplicationData* at +0x38 in all builds\r\n        "mbPaused": (c_bool, {}),
        "muPlayerSaveSlot": (c_int32, {"1.38": 0x40}),
    }

    @legacy_hook("cGcApplication::Update")
    def Update(self, this: c_uint64): ...


class cGcApplicationLocalLoadState(gen.cGcApplicationLocalLoadState, Structure):
    @legacy_hook("cGcApplicationLocalLoadState::GetRespawnReason")
    def GetRespawnReason(self, this: c_uint64) -> c_int32: ...


@versioned_struct
class cGcSimulation(gen.cGcSimulation, Structure):
    _vfields_ = {}

    @legacy_hook("cGcSimulation::Construct")
    def Construct(self, this: c_uint64): ...

    @legacy_hook("cGcSimulation::Destruct")
    def Destruct(self, this: c_uint64): ...


@versioned_struct
class cGcGameState(gen.cGcGameState, Structure):
    _vfields_ = {}

    @legacy_hook("cGcGameState::LoadFromPersistentStorage")
    def LoadFromPersistentStorage(self, this: c_uint64, *args): ...

    # Legacy has no distinct save-completed callback; this is cGcGameState::
    # WriteStateToStorage, whose .after is the closest equivalent.
    @legacy_hook("cGcGameState::OnSaveProgressCompleted")
    def OnSaveProgressCompleted(self, this: c_uint64, *args): ...


@versioned_struct
class cGcPlanet(gen.cGcPlanet, Structure):
    # Offsets are exe-RE'd from cGcPlanet::cGcPlanet/Construct/Generate/SetupRegionMap across
    # builds (tools/legacy_re/field_evidence.py; adversarially verified). mRegionMap and
    # mPlanetGenerationInputData are embedded sub-objects, so the offset is the sub-object
    # start, not a pointer value. mpEnvProperties/mPlanetDiscoveryData not yet located.
    _vfields_ = {
        "miPlanetIndex": (c_int32, {"1.09.1": 0x50, "1.13": 0x50, "1.24": 0x50, "1.38": 0x58}),
        "mPlanetGenerationInputData": (c_uint64, {"1.09.1": 0x2F00, "1.13": 0x3010, "1.24": 0x3010, "1.38": 0x3550}),
        "mRegionMap": (c_uint64, {"1.09.1": 0x2FC0, "1.13": 0x30F0, "1.24": 0x30F0, "1.38": 0x3630}),
        "mNode": (TkHandle, {"1.09.1": 0xE7CE8, "1.13": 0x12E318, "1.24": 0x12E318, "1.38": 0x12E868}),
        "mPosition": (Vector3f, {"1.09.1": 0xE7D00, "1.13": 0x12E330, "1.24": 0x12E330, "1.38": 0x12E880}),
        "mpEnvProperties": (c_uint64, {}),
        "mPlanetDiscoveryData": (c_uint64, {}),
    }

    @legacy_hook("cGcPlanet::SetupRegionMap")
    def SetupRegionMap(self, this: c_uint64): ...

    @legacy_hook("cGcPlanet::Generate")
    def Generate(self, this: c_uint64, *args): ...


@versioned_struct
class cGcSolarSystem(gen.cGcSolarSystem, Structure):
    # Base of the 6 inline cGcPlanet objects (stride = sizeof cGcPlanet); from the 6-iteration
    # loop in cGcSolarSystem::Construct. The offset is the array base, not a pointer.
    _vfields_ = {
        "maPlanets": (c_uint64, {"1.09.1": 0x16B0, "1.13": 0x17A0, "1.24": 0x17A0, "1.38": 0x1C30}),
    }

    @legacy_hook("cGcSolarSystem::OnEnterPlanetOrbit")
    def OnEnterPlanetOrbit(self, this: c_uint64, *args): ...

    @legacy_hook("cGcSolarSystem::OnLeavePlanetOrbit")
    def OnLeavePlanetOrbit(self, this: c_uint64, lbAnnounceOSD: c_bool): ...


@versioned_struct
class cGcShipHUD(gen.cGcShipHUD, Structure):
    # mHeadsUpGUI is the embedded HEADSUP.MXML cGcNGui (offset is sub-object start), named from
    # cGcShipHUD::LoadData's MXML loads; miSelectedPlanet from RenderHeadsUp. PanelVisible not found.
    _vfields_ = {
        "mHeadsUpGUI": (c_uint64, {"1.09.1": 0x22930, "1.13": 0x23030, "1.24": 0x23030, "1.38": 0x23AD0}),
        "miSelectedPlanet": (c_int32, {"1.09.1": 0x212A8, "1.13": 0x21998, "1.24": 0x21998, "1.38": 0x22438}),
        # 4-byte flag immediately after miSelectedPlanet (the ship's planet-select panel).
        "mbSelectedPlanetPanelVisible": (c_int32, {"1.09.1": 0x212AC, "1.13": 0x2199C, "1.24": 0x2199C, "1.38": 0x2243C}),
    }

    @legacy_hook("cGcShipHUD::LoadData")
    def LoadData(self, this: c_uint64): ...

    @legacy_hook("cGcShipHUD::RenderHeadsUp")
    def RenderHeadsUp(self, this: c_uint64): ...

    @legacy_hook("cGcShipHUD::RenderFlightHUD")
    def RenderFlightHUD(self, this: c_uint64): ...


class cGcNGuiLayer(gen.cGcNGuiLayer, Structure):
    @legacy_hook("cGcNGuiLayer::FindTextRecursive")
    def FindTextRecursive(self, this: c_uint64, lTextID: c_uint64) -> c_uint64: ...

    @legacy_hook("cGcNGuiLayer::FindElementRecursive")
    def FindElementRecursive(self, this: c_uint64, lID: c_uint64, leType: c_int32) -> c_uint64: ...


@versioned_struct
class cGcNGuiText(Structure):
    # mpTextData at +0x60 in all builds (from cGcNGuiText::EditElement).
    _vfields_ = {
        "mpTextData": (c_uint64, 0x60),
    }


@versioned_struct
class cGcEnvironment(Structure):
    """The player environment tracker (called cGcPlayerEnvironment in Newton/mods).

    Located at cGcApplicationData + 0x101360 (1.38). The ctor (FUN_140678FC0 in 1.38)
    initializes two state blocks (planet-side and space-side), each with a
    nearest-planet-index (int, -1 = none) and distance-from-planet (float, FLT_MAX = far).
    """
    _vfields_ = {
        # First state block (planet-side)
        "miNearestPlanetIndex": (c_int32, {"1.38": 0x528}),
        "mfDistanceFromPlanet": (c_float, {"1.38": 0x52C}),
        # Second state block (space-side) � same layout at +0x2C0 offset
        "miNearestPlanetIndexSpace": (c_int32, {"1.38": 0x7E8}),
        "mfDistanceFromPlanetSpace": (c_float, {"1.38": 0x7EC}),
    }


@versioned_struct
class cGcMarkerPoint(gen.cGcMarkerPoint, Structure):
    # mCustomName is a cTkFixedString<0x40> at +0x38 in every build (cleared in Reset via
    # strncpy(this+0x38, "", 0x40)); ctor + Reset are now located in offsets.json.
    _vfields_ = {
        "mCustomName": (c_char * 0x40, 0x38),
    }

    @legacy_hook("cGcMarkerPoint::IsEqual")
    def IsEqual(self, this: c_uint64, other: c_uint64, *args) -> c_bool: ...


@versioned_struct
class cTkDynamicGravityControl(gen.cTkDynamicGravityControl, Structure):
    _vfields_ = {
        "maGravityPoints": (c_uint64, {}),
    }

    @legacy_hook("cTkDynamicGravityControl::Construct")
    def Construct(self, this: c_uint64): ...

    @legacy_hook("cTkDynamicGravityControl::cTkDynamicGravityControl")
    def cTkDynamicGravityControl(self, this: c_uint64): ...

    @legacy_hook("cTkDynamicGravityControl::GetGravity")
    def GetGravity(self, this: c_uint64, *args): ...


class cTkStopwatch(gen.cTkStopwatch, Structure):
    @legacy_hook("cTkStopwatch::GetDurationInSeconds")
    def GetDurationInSeconds(self, this: c_uint64) -> c_float: ...


class cGcPlayerBasePersistentBuffer(gen.cGcPlayerBasePersistentBuffer, Structure):
    """Base-building persistence. 1.09.1 predates base building entirely."""

    @legacy_hook("cGcPlayerBasePersistentBuffer::LoadGalacticAddress")
    def LoadGalacticAddress(self, this: c_uint64, *args): ...


class cGcRewardManager(gen.cGcRewardManager, Structure):
    @legacy_hook("cGcRewardManager::GiveGenericReward")
    def GiveGenericReward(self, this: c_uint64, lRewardID: c_uint64, *args): ...


class cGcInteractionComponent(gen.cGcInteractionComponent, Structure):
    @legacy_hook("cGcInteractionComponent::GetPuzzle")
    def GetPuzzle(self, this: c_uint64) -> c_uint64: ...


@versioned_struct
class cGcAlienPuzzleEntry(Structure):
    _vfields_ = {
        "Id": (c_uint64, 0x0),
        "Options": (c_uint64, {"1.09.1": 0x420, "1.13": 0x420, "1.24": 0x420, "1.38": 0x4B0}),
    }


class Engine(gen.Engine):
    """Engine functions that are called directly (not hooked)."""

    @legacy_hook("Engine::ShiftAllTransformsForNode", static=True)
    def ShiftAllTransformsForNode(node: c_uint64, shift: c_uint64): ...

    @legacy_hook("Engine::GetNodeAbsoluteTransMatrix", static=True)
    def GetNodeAbsoluteTransMatrix(node: c_uint64, matrix: c_uint64): ...


class _EngineModules:
    """Placeholder for the modern engine-module registry; nothing is mapped yet."""

    def __getattr__(self, name):
        _warn_once(
            f"engine_modules.{name}",
            f"engine_modules.{name} is not mapped in this build; returning None.",
        )
        return None


engine_modules = _EngineModules()

