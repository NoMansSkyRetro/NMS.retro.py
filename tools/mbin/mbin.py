"""MBIN header reader.

An ``.MBIN`` file is compiled NMS metadata. Its 0x60-byte header (calibrated against
GCENVIRONMENTGLOBALS.GLOBAL.MBIN in every legacy build) is:

    0x00  u32   magic      = 0xCCCCCCCC  (standard MBIN; 0xDDDDDDDD is the "v2"/MBINC form)
    0x04  u32   version    format/compiler version number (e.g. 2500)
    0x08  u64   timestamp  the version stamp libMBIN keys on, decimal YYYYMMDDHHMM
    0x10  u64   guid       the root template's class GUID
    0x18  char[0x40] name  the root template class, e.g. "cGcEnvironmentGlobals"

The ``timestamp`` is what pins the matching libMBIN release/era for a build, so the
struct definitions we python-ify come from the right point in libMBIN's history.
"""
import struct
from dataclasses import dataclass

MAGIC_STD = 0xCCCCCCCC
MAGIC_V2 = 0xDDDDDDDD


@dataclass
class MbinHeader:
    magic: int
    version: int
    timestamp: int      # decimal YYYYMMDDHHMM
    guid: int
    template: str

    @property
    def ok(self) -> bool:
        return self.magic in (MAGIC_STD, MAGIC_V2)

    @property
    def stamp_str(self) -> str:
        s = str(self.timestamp)
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}" if len(s) == 12 else s


def read_header(data: bytes) -> MbinHeader:
    magic, version, timestamp, guid = struct.unpack_from("<IIQQ", data, 0)
    name = data[0x18:0x58].split(b"\0", 1)[0].decode("ascii", "replace")
    return MbinHeader(magic, version, timestamp, guid, name)
