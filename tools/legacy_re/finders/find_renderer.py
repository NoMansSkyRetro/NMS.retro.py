"""Finder for the `renderer` batch (cEg*/renderer/graphics/geometry-streaming).

Deterministic, self-contained derivation of NOT_YET_FOUND renderer function
addresses across the four legacy builds. Prints one JSON object to stdout
(pure JSON); all reasoning is logged to stderr.

Two targets are located with two independent signals each; the remaining 26 are
left honestly `unresolved` (see the reasons in the output and the notes below).

What is found and how
---------------------
* cEgTextureResource::LoadFromDds -- string lock. Exactly one function in each
  build references the DDS error strings ('Invalid DDS header', 'Unsupported DDS
  texture type', 'Unsupported DDS pixel format'). That single owner is LoadFromDds.
  1.13/1.24/1.38 are already curated in offsets.json (this reproduces them and
  agrees); 1.09.1 (0x140C859B0) was NOT_YET_FOUND and is newly located.

* cTkTextureBase::CalculateTextureSize -- anchored callee + structural match.
  It is a leaf function (calls nothing) directly called by LoadFromDds, and its
  body is an unmistakable switch(eTexFormat) that returns w*h*depth*bytesPerPixel
  with the DXT block-rounding ((x+3)>>2) branches. In each build exactly one
  LoadFromDds callee has that shape. Signature (uint(eTexFormat,int,int,int))
  matches. Located in all four builds.

Why the rest are unresolved
---------------------------
The renderer/geometry targets reference no distinctive strings that survive into
the legacy decompilation, and their imm64 constants are common hash seeds (FNV
basis/prime, MurmurHash3 c1/c2/fmix) shared by hundreds of functions, so
fingerprinting cannot lock them. Call-graph anchoring is also weak: their
distinctive callees/callers are themselves NOT_YET_FOUND, leaving only common
allocators (operator new, cTkMemoryManager::Free) as anchors, which produce
ties or verified false positives (e.g. the best call-graph candidate for
cTkGraphicsAPI::CreateVertexBuffer decompiles to a glGetActiveUniform lookup,
and for ProcessOnlyStreamRequests to __security_check_cookie). The automated
propagation (propagate_symbols.py) already failed to lock these 26 for the same
reasons; an honest unresolved is preferred over a guess. Two of them
(FindVertexBufferIndexByHash, GetVertexBufferByIndex) do not even exist as
standalone functions in the 4.13 reference build, so there is nothing to transfer.
"""

import json
import re
import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import BUILDS, Binary  # noqa: E402

BUILD_LIST = list(BUILDS)  # 1.09.1, 1.13, 1.24, 1.38

# Distinctive DDS strings referenced only by cEgTextureResource::LoadFromDds.
DDS_STRINGS = [
    b"Invalid DDS header",
    b"Unsupported DDS texture type",
    b"Unsupported DDS pixel format",
]


def log(*a):
    print(*a, file=sys.stderr)


def string_vas(bin, needle):
    """VAs of every standalone NUL-terminated occurrence of `needle`."""
    out = []
    for m in re.finditer(re.escape(needle) + b"\0", bin.data):
        off = m.start()
        if bin.data[off - 1] != 0:
            continue
        va = bin.file_offset_to_va(off)
        if va is not None:
            out.append(va)
    return out


def text_section(bin):
    for s in bin.sections:
        if s.name == ".text":
            return s
    return None


def containing_function(bin, va):
    """(addr, size, name, decomp) of the function whose body contains `va`."""
    row = bin.db.execute(
        "SELECT address, size, name, raw_decomp FROM decompilations "
        "WHERE address <= ? ORDER BY address DESC LIMIT 1",
        (va,),
    ).fetchone()
    if row and row[0] <= va < row[0] + (row[1] or 0):
        return row
    return None


def refs_to_va(bin, target_va):
    """Function start VAs that contain a rel32 in .text pointing at target_va.

    Vectorized: at every byte offset `p` of .text the stored little-endian int32
    is a candidate rel32 whose instruction ends at text_base+p+4, so it points at
    target_va exactly when int32 == target_va - text_base - p - 4.
    """
    sec = text_section(bin)
    raw, rva, rsize = sec.raw_offset, sec.virtual_address, sec.raw_size
    text_base = 0x140000000 + rva
    t = np.frombuffer(bin.data, dtype=np.uint8, count=rsize, offset=raw)
    i32 = (
        t[0:-3].astype(np.uint32)
        | (t[1:-2].astype(np.uint32) << 8)
        | (t[2:-1].astype(np.uint32) << 16)
        | (t[3:].astype(np.uint32) << 24)
    ).astype(np.int32).astype(np.int64)
    p = np.arange(len(i32), dtype=np.int64)
    want = target_va - text_base - 4 - p
    owners = set()
    for pos in np.nonzero(i32 == want)[0]:
        owner = containing_function(bin, int(text_base + pos))
        if owner:
            owners.add(owner[0])
    return owners


def find_loadfromdds(bin):
    """The unique function referencing the DDS error strings."""
    vote = {}
    for needle in DDS_STRINGS:
        vas = string_vas(bin, needle)
        if not vas:
            log(f"  [{bin.build}] string {needle!r} absent")
            continue
        owners = set()
        for va in vas:
            owners |= refs_to_va(bin, va)
        log(f"  [{bin.build}] {needle!r}: owners {[hex(o) for o in owners]}")
        for o in owners:
            vote[o] = vote.get(o, 0) + 1
    if not vote:
        return None
    best = max(vote, key=vote.get)
    if vote[best] < 2:  # require >=2 of the distinctive strings
        return None
    if bin.function_at(best) is None:
        return None
    return best


SIZE_SWITCH = re.compile(r"param_\d+ \* param_\d+ \* param_\d+ \* ")


def find_calculate_texture_size(bin, loadfromdds_va):
    """LoadFromDds's leaf callee whose body is the eTexFormat size switch."""
    row = bin.function_at(loadfromdds_va)
    if row is None:
        return None
    lfd_row = bin.db.execute(
        "SELECT size FROM decompilations WHERE address=?", (loadfromdds_va,)
    ).fetchone()
    size = lfd_row[0] if lfd_row else 0
    off = bin.va_to_file_offset(loadfromdds_va)
    text_base_off = loadfromdds_va - off  # va = off + text_base_off
    callees = set()
    data = bin.data
    for i in range(off, off + size - 5):
        if data[i] == 0xE8:  # call rel32
            disp = struct.unpack_from("<i", data, i + 1)[0]
            tgt = (i + text_base_off) + 5 + disp
            if bin.function_at(tgt) is not None:
                callees.add(tgt)
    cands = []
    for c in callees:
        r = bin.function_at(c)
        name, addr, csize, decomp = r
        parts = decomp.split("{", 1)
        if len(parts) != 2:
            continue
        head, body = parts
        nargs = len(set(re.findall(r"param_\d+", head)))
        # leaf size switch: 4 args, a switch, and the w*h*d*bpp multiply chain
        if "switch" in body and SIZE_SWITCH.search(body) and nargs == 4:
            # confirm it is a leaf (its body issues no calls of its own)
            if "(*" not in body and re.search(r"\bFUN_[0-9a-f]+\(", body) is None:
                cands.append(c)
    if len(cands) == 1:
        return cands[0]
    log(f"  [{bin.build}] CalculateTextureSize candidates: {[hex(c) for c in cands]}")
    return None


UNRESOLVED = {
    "EgInstancedModelExtension::cEgInstancedMeshNode::RenderAsync":
        "no distinctive strings; imm64 are common (0xAAAA.. reciprocal); call-graph ambiguous (ratio 1.0)",
    "GeometryStreaming::cEgGeometryStreamer::FindVertexBufferIndexByHash":
        "inlined in 4.13 (no reference VA) and no strings/imm64; nothing to transfer",
    "GeometryStreaming::cEgGeometryStreamer::GetVertexBufferByIndex":
        "inlined in 4.13 (no reference VA) and no strings/imm64; nothing to transfer",
    "GeometryStreaming::cEgGeometryStreamer::OnBufferLoadFinish":
        "no strings/imm64; no mapped call-graph neighbours in legacy",
    "GeometryStreaming::cEgGeometryStreamer::RequestStream":
        "'.GEOMETRY.' string does not survive into legacy decomp; imm64 are FNV seeds; call-graph ambiguous",
    "GeometryStreaming::cEgStreamRequests::ProcessOnlyStreamRequests":
        "call-graph best candidate verified false (__security_check_cookie); no other signal",
    "cEgDrawGeometry::Draw":
        "no strings/imm64; no mapped call-graph neighbours in legacy",
    "cEgGeometryResource::CloneOriginalVertDataToIndex":
        "no strings/imm64; no mapped call-graph neighbours in legacy",
    "cEgGeometryResource::CreateVertexInfoForHash":
        "no strings/imm64; no mapped call-graph neighbours in legacy",
    "cEgGeometryResource::Load":
        "only 1 common mapped callee; call-graph ambiguous (ratio 1.0)",
    "cEgGeometryResource::ParseData":
        "'AssistanceType' shared by 4 funcs, none matches the parser; call-graph ambiguous",
    "cEgGeometryResource::cEgGeometryResource":
        "imm64 0xC4CEB9FE.. is a common hash seed; no mapped call-graph neighbours",
    "cEgMeshNode::ParsingFunc":
        "call-graph candidates tie (ratio 1.0); no structural confirmation",
    "cEgModelNode::Animate":
        "no strings/imm64; no mapped call-graph neighbours in legacy",
    "cEgModelNode::UpdateGeometry":
        "imm64 0x7FFF.. common; only 1 mapped callee; call-graph ambiguous",
    "cEgRenderer::DrawMeshes":
        "no strings/imm64; no mapped call-graph neighbours in legacy",
    "cEgRenderer::DrawRenderables":
        "no strings/imm64; no mapped call-graph neighbours in legacy",
    "cEgRenderer::SetupMeshGeometry":
        "imm64 0xAAAA.. reciprocal common; only 1 mapped callee; call-graph ambiguous",
    "cEgRenderer::SetupMeshMaterial":
        "no strings/imm64; only common mapped callers; call-graph ambiguous",
    "cEgRendererBase::ApplyVertexLayout":
        "imm64 are MurmurHash3 c1/c2/fmix constants shared by many funcs; call-graph ambiguous",
    "cEgSceneNodeData::SetRelativeTransform":
        "no strings/imm64; only 1 common mapped caller; call-graph ambiguous",
    "cTkGraphicsAPI::CreateIndexBuffer":
        "GL buffer creation inlined into one monolithic function; no per-symbol anchor",
    "cTkGraphicsAPI::CreateVertexBuffer":
        "call-graph best candidate (ratio 2.55) verified false (glGetActiveUniform lookup); no other signal",
    "cTkGraphicsAPI::GetVertexBufferData":
        "no strings/imm64; no mapped call-graph neighbours in legacy",
    "cTkTexture::CopyPixelDataToBuffer":
        "no strings/imm64; no mapped call-graph neighbours in legacy",
    "cTkTexture::CreateEmptyTexture":
        "call-graph candidate 0x140FDEF70 has 7 args vs 14 modern and no confirming signal; ambiguous",
}


def main():
    functions = {}
    for build in BUILD_LIST:
        log(f"[{build}] loading binary + db")
        bin = Binary(build)

        lfd = find_loadfromdds(bin)
        if lfd is not None:
            functions.setdefault("cEgTextureResource::LoadFromDds", {})[build] = f"0x{lfd:X}"
            log(f"[{build}] LoadFromDds = 0x{lfd:X}")
            cts = find_calculate_texture_size(bin, lfd)
            if cts is not None:
                functions.setdefault("cTkTextureBase::CalculateTextureSize", {})[build] = f"0x{cts:X}"
                log(f"[{build}] CalculateTextureSize = 0x{cts:X}")
            else:
                log(f"[{build}] CalculateTextureSize not uniquely identified")
        else:
            log(f"[{build}] LoadFromDds not found")

    print(json.dumps({"functions": functions, "unresolved": UNRESOLVED}, indent=1))


if __name__ == "__main__":
    main()
