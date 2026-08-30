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


_warned: set = set()


def _warn_once(key: str, message: str):
    if key not in _warned:
        _warned.add(key)
        logger.warning(message)


class DisabledHook:
    """Stand-in for a hook whose address is unknown in the running build.

    Keeps the FunctionHook API shape so mods import and load cleanly: their detours
    just never fire (with a warning at load time), and calling the game function
    warns once and returns None instead of raising, so mods degrade gracefully.
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

    def __get__(self, instance, owner=None):
        # Also stand in for bound method calls on struct instances.
        return self

    def __call__(self, *args, **kwargs):
        version = CURRENT_VERSION.value if CURRENT_VERSION else "<unknown build>"
        _warn_once(
            f"call:{self._name}",
            f"{self._name} has no known address in {version}; call ignored (returning None).",
        )
        return None


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


def versioned_struct(cls):
    """Build a partial struct from per-version field specs.

    The class declares ``_vfields_`` as ``name -> (ctype, offset_spec)`` where
    ``offset_spec`` is either an int (same offset in every build) or a
    ``{version: offset}`` dict. Fields with an offset in the running build become
    real ctypes fields (via pyMHF's partial_struct); the rest read as None with a
    one-time warning, so a mod touching a field that does not exist in this build
    degrades instead of crashing.
    """
    from typing import Annotated

    from pymhf.core.structs import Field, partial_struct

    version = CURRENT_VERSION.value if CURRENT_VERSION else None
    available = []
    missing = set()
    for name, (ctype, spec) in getattr(cls, "_vfields_", {}).items():
        offset = spec if isinstance(spec, int) else (spec.get(version) if version else None)
        if offset is None:
            missing.add(name)
        else:
            available.append((offset, name, ctype))
    for offset, name, ctype in sorted(available):
        cls.__annotations__[name] = Annotated[ctype, Field(ctype, offset)]
    cls = partial_struct(cls)
    cls._missing_fields_ = frozenset(missing) | frozenset(getattr(cls, "_missing_fields_", ()))

    def __getattr__(self, name):
        if name in type(self)._missing_fields_:
            version_ = CURRENT_VERSION.value if CURRENT_VERSION else "<unknown build>"
            _warn_once(
                f"field:{type(self).__name__}.{name}",
                f"{type(self).__name__}.{name} is not mapped in {version_}; returning None.",
            )
            return None
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

    cls.__getattr__ = __getattr__
    return cls
