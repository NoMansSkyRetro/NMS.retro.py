"""Per-version address data and the hook helper built on it.

The four supported builds are frozen forever, so functions are located by static
addresses extracted from the Ghidra decompilation databases (see tools/legacy_re/)
rather than by byte-pattern scanning. `offsets.json` maps
``"Class::Function" -> {"1.13": "0x1405B1F80", ...}``; a missing or null entry means
the function has not been located in that build yet, and any hook on it is disabled
with a warning instead of crashing.

Addresses are Ghidra-style virtual addresses assuming the preferred image base
0x140000000; pyMHF gets them as offsets relative to the actual module base.
"""

import json
from logging import getLogger
from pathlib import Path
from typing import Optional

from pymhf.core.hooking import function_hook, static_function_hook

from nmspy.versions import CURRENT_VERSION

logger = getLogger(__name__)

STATIC_BASE = 0x140000000

with open(Path(__file__).parent / "offsets.json") as _f:
    _DATA: dict = json.load(_f)

FUNCTIONS: dict = _DATA["functions"]
GLOBALS: dict = _DATA["globals"]


def offset_for(name: str) -> Optional[int]:
    """The module-relative offset of a named function in the running build, or None."""
    if CURRENT_VERSION is None:
        return None
    address = (FUNCTIONS.get(name) or {}).get(CURRENT_VERSION.value)
    return int(address, 16) - STATIC_BASE if address else None


def global_offset_for(name: str) -> Optional[int]:
    """The module-relative offset of a named global in the running build, or None."""
    if CURRENT_VERSION is None:
        return None
    address = (GLOBALS.get(name) or {}).get(CURRENT_VERSION.value)
    return int(address, 16) - STATIC_BASE if address else None


class DisabledHook:
    """Stand-in for a hook whose address is unknown in the running build.

    Keeps the FunctionHook API shape so mods import and load cleanly; their detours
    just never fire (with a warning at load time), and calling the game function
    raises with a clear message.
    """

    def __init__(self, name: str):
        self._name = name

    def _warn(self, detour):
        version = CURRENT_VERSION.value if CURRENT_VERSION else "<unknown build>"
        logger.warning(
            f"{self._name} has no known address in {version}; "
            f"{detour.__qualname__} will never be called."
        )
        return detour

    before = _warn
    after = _warn

    def __call__(self, *args, **kwargs):
        raise RuntimeError(f"{self._name} has no known address in this game build.")


def legacy_hook(name: str, static: bool = False):
    """``function_hook`` bound to the running build's address for `name`.

    Falls back to a DisabledHook when the address is unknown so partial per-version
    coverage degrades gracefully.
    """
    offset = offset_for(name)
    if offset is None:
        return lambda func: DisabledHook(name)
    if static:
        return static_function_hook(offset=offset)
    return function_hook(offset=offset)
