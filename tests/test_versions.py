from pathlib import Path

import pytest

from nmspy.versions import GameVersion, detect_version

EXE_ROOT = Path(r"E:\NMSLegacy")

BINARIES = {
    GameVersion.v1_09_1: EXE_ROOT / "no_mans_sky_v1.09.1" / "Binaries" / "NMS.exe",
    GameVersion.v1_13: EXE_ROOT / "no_mans_sky_v1.13" / "Binaries" / "NMS.exe",
    GameVersion.v1_24: EXE_ROOT / "no_mans_sky_v1.24" / "Binaries" / "NMS.exe",
    GameVersion.v1_38: EXE_ROOT / "no_mans_sky_v1.38" / "Binaries" / "NMS.exe",
}


@pytest.mark.parametrize("expected,path", BINARIES.items(), ids=[v.value for v in BINARIES])
def test_detects_steam_builds(expected, path):
    if not path.exists():
        pytest.skip(f"{path} not present")
    assert detect_version(str(path)) is expected


def test_unknown_build_returns_none(tmp_path):
    # A minimal fake PE with an unknown timestamp.
    fake = tmp_path / "NMS.exe"
    header = bytearray(0x100)
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")  # e_lfanew
    header[0x80:0x84] = b"PE\0\0"
    header[0x88:0x8C] = (0x12345678).to_bytes(4, "little")  # TimeDateStamp
    fake.write_bytes(header)
    assert detect_version(str(fake)) is None
