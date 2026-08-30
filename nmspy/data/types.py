"""Legacy game types and hooked functions.

Rebuilt from scratch for the four legacy builds this fork targets. The modern (4.x)
definitions this file replaced live in upstream NMS.py and in git history.

Hooks resolve to per-build static addresses from ``offsets.json`` (derived with the
scripts in ``tools/legacy_re/``). A hook with no address for the running build is
disabled with a warning instead of failing, so coverage can grow build by build.

Argument annotations are deliberately raw (``c_uint64`` addresses) until each struct's
legacy layout is verified; see tools/legacy_re/findings.md for what is known so far.
"""

from ctypes import c_float, c_uint64

from pymhf.core.hooking import Structure

from nmspy.data.offsets import legacy_hook


class cTkFSM(Structure):
    # Layout notes in tools/legacy_re/findings.md; fields added as they are verified.

    @legacy_hook("cTkFSM::Update")
    def Update(self, this: c_uint64, lfTimestep: c_float): ...

    @legacy_hook("cTkFSM::StateChange")
    def StateChange(self, this: c_uint64, lNewStateID: c_uint64): ...


class cGcApplication(cTkFSM):
    """The static application singleton (a cTkFSM whose states are the App* states)."""

    @legacy_hook("cGcApplication::Update")
    def Update(self, this: c_uint64): ...
