"""Detection of which legacy NMS build is running.

Each supported build is identified by the 4-byte TimeDateStamp in its PE header. This
is unique per build, survives SteamStub packing (the header is not encrypted), and
works on both the on-disk file and the in-memory image, so no hashing is needed.
"""

import struct
from enum import Enum
from logging import getLogger
from typing import Optional

logger = getLogger(__name__)


class GameVersion(str, Enum):
    v1_09_1 = "1.09.1"
    v1_13 = "1.13"
    v1_24 = "1.24"
    v1_38 = "1.38"


# Steam builds. Note the GOG 1.09.1 binary is a different build (0x57FF732B, linked
# ten minutes after the Steam one) with a different code layout; it is not supported
# until its addresses are mapped separately.
_TIMESTAMPS = {
    0x57FF70CA: GameVersion.v1_09_1,
    0x584983DE: GameVersion.v1_13,
    0x58D42A08: GameVersion.v1_24,
    0x59CE2F3C: GameVersion.v1_38,
}


def detect_version(binary_path: str) -> Optional[GameVersion]:
    """Identify a NMS.exe by its PE header TimeDateStamp."""
    with open(binary_path, "rb") as f:
        header = f.read(0x200)
    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    timestamp = struct.unpack_from("<I", header, pe_offset + 8)[0]
    version = _TIMESTAMPS.get(timestamp)
    if version is None:
        logger.error(
            f"Unrecognized NMS build (PE TimeDateStamp 0x{timestamp:08X}). "
            f"Supported builds: {', '.join(v.value for v in GameVersion)} (Steam)."
        )
    return version


def _detect_running_version() -> Optional[GameVersion]:
    import sys

    # Importing pymhf outside the injected process side-effects (interactive config
    # prompts), so only look at it when it is already loaded, which is always the
    # case when pyMHF injected us into the game.
    if "pymhf.core._internal" not in sys.modules:
        return None
    from pymhf.core._internal import BINARY_PATH
    if not BINARY_PATH:
        return None
    try:
        return detect_version(BINARY_PATH)
    except Exception:
        logger.exception("Could not detect the game version")
        return None


#: The build pyMHF injected into; None when running outside the game (eg. tests).
CURRENT_VERSION: Optional[GameVersion] = _detect_running_version()

if CURRENT_VERSION is not None:
    logger.info(f"Detected No Man's Sky {CURRENT_VERSION.value}")
