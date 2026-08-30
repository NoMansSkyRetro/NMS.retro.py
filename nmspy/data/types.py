"""Legacy game types and hooked functions.

Rebuilt from scratch for the four legacy builds this fork targets. The modern (4.x)
definitions this file replaced live in upstream NMS.py and in git history.

Hooks resolve to per-build static addresses from ``offsets.json`` (derived with the
scripts in ``tools/legacy_re/``). A hook with no address for the running build is
disabled with a warning instead of failing, so coverage can grow build by build.

Pointer arguments are annotated as raw ``c_uint64`` addresses until each struct's
legacy layout is verified; see tools/legacy_re/findings.md for what is known so far.
"""

from ctypes import c_bool, c_char, c_float, c_uint64
from typing import Annotated

from pymhf.core.hooking import Structure
from pymhf.core.structs import Field, partial_struct

from nmspy.data.offsets import legacy_hook


@partial_struct
class cTkFSM(Structure):
    #: The active cTkFSMState*.
    mpCurrState: Annotated[int, Field(c_uint64, 0x10)]
    #: The requested next state ID; FSM_NoState when no transition is pending.
    macPendingStateID: Annotated[bytes, Field(c_char * 0x10, 0x18)]

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


class cTkFSMState(Structure):
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


@partial_struct
class cGcApplication(cTkFSM):
    """The static application singleton (a cTkFSM whose states are the App* states)."""

    @legacy_hook("cGcApplication::Update")
    def Update(self, this: c_uint64): ...
