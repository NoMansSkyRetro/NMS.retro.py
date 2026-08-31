"""Minimal read-only PSARC (.pak) reader for the legacy No Man's Sky archives.

NMS ships its metadata in PSARC v1.4 archives (magic ``PSAR``, zlib blocks). This
extracts the manifest and individual files (e.g. ``*.MBIN``) without any external tool,
so the struct-regeneration pipeline can read the shipped metadata straight from a legacy
install's ``GAMEDATA/PCBANKS/*.pak``.

    from psarc import Psarc
    pak = Psarc(r"E:\\NMSLegacy\\no_mans_sky_v1.38\\GAMEDATA\\PCBANKS\\NMSARC.12FE2434.pak")
    for name in pak.names:            # forward-slash paths, as stored
        if name.upper().endswith(".MBIN"):
            data = pak.read(name)     # decompressed bytes

Format: 32-byte header, then N fixed-size TOC entries (16-byte name-MD5, 4-byte first
block index, 5-byte uncompressed size, 5-byte archive offset), then the block-size table
(one entry per compressed block, width set by block_size; 0 means a full uncompressed
block). Entry 0 is the newline-separated filename manifest for entries 1..N.
"""
import struct
import zlib
from pathlib import Path


class Psarc:
    def __init__(self, path):
        self.path = Path(path)
        with open(self.path, "rb") as f:
            head = f.read(32)
            if head[:4] != b"PSAR":
                raise ValueError(f"not a PSARC archive: {self.path} (magic {head[:4]!r})")
            # head[4:8] = version (00 01 00 04), head[8:12] = compression ("zlib")
            toc_len, ent_size, n_ent, self.block_size, _flags = struct.unpack(">IIIII", head[12:32])
            entries = []
            for _ in range(n_ent):
                e = f.read(ent_size)
                entries.append((
                    struct.unpack(">I", e[16:20])[0],       # first block index
                    int.from_bytes(e[20:25], "big"),        # uncompressed length
                    int.from_bytes(e[25:30], "big"),         # archive offset
                ))
            self.entries = entries
            width = 1 if self.block_size <= 0x100 else 2 if self.block_size <= 0x10000 else \
                3 if self.block_size <= 0x1000000 else 4
            bstab = f.read(toc_len - (32 + n_ent * ent_size))
            self.blocks = [int.from_bytes(bstab[i:i + width], "big") for i in range(0, len(bstab), width)]
        manifest = self._extract(self.entries[0]).decode("utf-8", "replace")
        # names line up with entries[1:]; keep as stored (forward slashes)
        self.names = [ln.strip() for ln in manifest.splitlines() if ln.strip()]

    def _extract(self, entry):
        block_idx, unc_len, offset = entry
        out = bytearray()
        with open(self.path, "rb") as f:
            f.seek(offset)
            bi = block_idx
            while len(out) < unc_len:
                bsz = self.blocks[bi]
                bi += 1
                if bsz == 0:                      # full uncompressed block
                    out += f.read(self.block_size)
                else:
                    chunk = f.read(bsz)
                    out += zlib.decompress(chunk) if chunk[:1] == b"\x78" else chunk
        return bytes(out[:unc_len])

    def _index(self, name):
        key = name.replace("\\", "/").lstrip("/").upper()
        for i, n in enumerate(self.names):
            if n.replace("\\", "/").lstrip("/").upper() == key:
                return i + 1                       # entries[0] is the manifest
        raise KeyError(name)

    def read(self, name):
        return self._extract(self.entries[self._index(name)])


if __name__ == "__main__":
    import sys
    pak = Psarc(sys.argv[1])
    mbins = [n for n in pak.names if n.upper().endswith(".MBIN")]
    print(f"{len(pak.names)} files, {len(mbins)} MBIN")
    for n in mbins[:15]:
        print("  ", n)
