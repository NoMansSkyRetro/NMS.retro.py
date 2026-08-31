"""Per-version address data and the hook helper built on it.

The four supported builds are frozen forever, so functions are located by static
addresses extracted from the Ghidra decompilation databases (see tools/legacy_re/)
rather than by byte-pattern scanning. `offsets.json` maps
``"Class::Function" -> {"1.13": "0x1405B1F80", ...}``; a missing or null entry means
the function has not been located in that build yet, and any hook on it is disabled
with a warning instead of crashing.

Addresses are Ghidra-style virtual addresses assuming the preferred image base
0x140000000; pyMHF gets them as offsets relative to the actual module base.

Per-entry metadata keys (all optional, prefixed ``_``):

- ``_note``   version-history note (e.g. why a feature is absent from a build).
- ``_names``  ``{version: "ActualName"}`` documenting the function's real name in a
              build when it differs from the entry key (functions get renamed across
              versions; the key stays the 4.13/upstream name).
- ``_aliases`` list of other names that resolve to this same function (renames or
              ICF-folded siblings). ``offset_for``/``availability`` accept an alias
              and transparently use the canonical entry.
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

#: alias name -> canonical entry name (built from every entry's ``_aliases``).
_ALIAS_OF: dict = {}
for _canon, _entry in FUNCTIONS.items():
    for _alias in (_entry.get("_aliases") or []):
        _ALIAS_OF[_alias] = _canon


def _entry_for(name: str) -> dict:
    """The offsets entry for a function name, following an alias if needed."""
    return FUNCTIONS.get(name) or FUNCTIONS.get(_ALIAS_OF.get(name, ""), {})


def version_name(name: str, version: Optional[str] = None) -> Optional[str]:
    """The function's actual name in a build, if it differs from the entry key.

    Returns None when the name is unchanged for that build (or unknown).
    """
    version = version or (CURRENT_VERSION.value if CURRENT_VERSION else None)
    if version is None:
        return None
    return (_entry_for(name).get("_names") or {}).get(version)

#: The function exists in this build but nobody has located its address yet.
NOT_YET_FOUND = "NOT_YET_FOUND"
#: The feature this function belongs to postdates this build entirely.
NOT_IN_THIS_VERSION = "NOT_IN_THIS_VERSION"
FOUND = "FOUND"


def _is_address(value) -> bool:
    return isinstance(value, str) and value.startswith("0x")


def availability(name: str):
    """(status, note) for a named function in the running build.

    status is FOUND, NOT_YET_FOUND, or NOT_IN_THIS_VERSION; note carries the
    version-history explanation when the data has one.
    """
    entry = _entry_for(name)
    note = entry.get("_note")
    if CURRENT_VERSION is None:
        return NOT_YET_FOUND, note
    value = entry.get(CURRENT_VERSION.value)
    if _is_address(value):
        return FOUND, note
    if value == NOT_IN_THIS_VERSION:
        return NOT_IN_THIS_VERSION, note
    return NOT_YET_FOUND, note


def offset_for(name: str) -> Optional[int]:
    """The module-relative offset of a named function in the running build, or None.

    Accepts either the canonical entry key or any of its ``_aliases``.
    """
    if CURRENT_VERSION is None:
        return None
    address = _entry_for(name).get(CURRENT_VERSION.value)
    return int(address, 16) - STATIC_BASE if _is_address(address) else None


def global_offset_for(name: str) -> Optional[int]:
    """The module-relative offset of a named global in the running build, or None."""
    if CURRENT_VERSION is None:
        return None
    address = (GLOBALS.get(name) or {}).get(CURRENT_VERSION.value)
    return int(address, 16) - STATIC_BASE if _is_address(address) else None


_warned: set = set()


def _warn_once(key: str, message: str):
    if key not in _warned:
        _warned.add(key)
        logger.warning(message)


class DisabledHook:
    """Stand-in for a hook that cannot resolve in the running build.

    Keeps the FunctionHook API shape so mods import and load cleanly: their detours
    just never fire (with a warning at load time), and calling the game function
    warns once and returns None instead of raising, so mods degrade gracefully.
    The status distinguishes a function nobody has located yet (NOT_YET_FOUND) from
    one whose feature postdates this build entirely (NOT_IN_THIS_VERSION).
    """

    def __init__(self, name: str, status: str = NOT_YET_FOUND, note: Optional[str] = None):
        self._name = name
        self._status = status
        self._note = note

    @property
    def status(self) -> str:
        return self._status

    def _reason(self) -> str:
        version = CURRENT_VERSION.value if CURRENT_VERSION else "<unknown build>"
        if self._status == NOT_IN_THIS_VERSION:
            reason = f"{self._name} does not exist in {version}"
        else:
            reason = f"{self._name} has not been located in {version} yet"
        return f"{reason} ({self._note})" if self._note else reason

    def _warn(self, detour):
        logger.warning(f"{self._reason()}; {detour.__qualname__} will never be called.")
        return detour

    before = _warn
    after = _warn

    def __get__(self, instance, owner=None):
        # Also stand in for bound method calls on struct instances.
        return self

    def __call__(self, *args, **kwargs):
        _warn_once(f"call:{self._name}", f"{self._reason()}; call ignored (returning None).")
        return None


def legacy_hook(name: str, static: bool = False):
    """``function_hook`` bound to the running build's address for `name`.

    Falls back to a DisabledHook when the address is unknown so partial per-version
    coverage degrades gracefully.
    """
    offset = offset_for(name)
    if offset is None:
        status, note = availability(name)
        return lambda func: DisabledHook(name, status, note)
    if static:
        return static_function_hook(offset=offset)
    return function_hook(offset=offset)


def versioned_struct(cls):
    """Build a partial struct from per-version field specs.

    The class declares ``_vfields_`` as ``name -> (ctype_spec, offset_spec)`` where
    ``offset_spec`` is either an int (same offset in every build) or a
    ``{version: offset}`` dict, and ``ctype_spec`` is either a single ctype (same type
    and size in every build) or a ``{version: ctype}`` dict (a field whose type or size
    changed across builds; the generator emits this so each build reads its own layout).
    Fields with both an offset and a ctype in the running build become real ctypes fields
    (via pyMHF's partial_struct); the rest read as None with a one-time warning, so a mod
    touching a field that does not exist in this build degrades instead of crashing.
    """
    from typing import Annotated

    from pymhf.core.structs import Field, partial_struct

    version = CURRENT_VERSION.value if CURRENT_VERSION else None
    available = []
    missing = set()
    for name, (ctype_spec, spec) in getattr(cls, "_vfields_", {}).items():
        offset = spec if isinstance(spec, int) else (spec.get(version) if version else None)
        ctype = ctype_spec if not isinstance(ctype_spec, dict) else (ctype_spec.get(version) if version else None)
        if offset is None or ctype is None:
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
