#!/usr/bin/env python3
"""Finder for the engine_scene batch, round 2.

Targets are Engine:: free/namespace scene-graph functions in egmain.cpp, address
adjacent to the round-1 cluster (GetNodeType/GetNodeName/AddNodes/... ).

Method: located and identified each function in 1.38 by decompiling the egmain
cluster, keyed off the node resolver (Engine::GetNodeName<1>, the TkHandle->node*
lookup) and the manager global.  The scene-node manager stores tree structure in a
struct-of-arrays at mgr+0x78 (stride 0x14):
    +0x00 numChildren (& 0x7fffffff)   +0x04 parent TkHandle
    +0x08 first-child dense idx         +0x10 next-sibling dense idx
Confirmed by the recursive mark-dirty helpers (MarkSelfOrAncestorTransformDirty /
MarkSelfOrDescendentsAABBDirty) which walk exactly those fields.  Each identified
1.38 function was then matched across the other three builds by identical body
(same resolver + same manager-field arithmetic); every emitted address is verified
here against the decompilation DB (function start + a body marker) before printing.

Only NOT_YET_FOUND slots are emitted.  Everything not isolated with two independent
signals is reported in `unresolved` rather than guessed.

Run from tools/legacy_re/ .  Pure JSON to stdout, logs to stderr.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import Binary  # noqa: E402


def log(*a):
    print(*a, file=sys.stderr)


# (name, build, va, body-marker that must appear in the decompilation).
# Markers are distinctive fragments of the verified bodies.
CANDIDATES = [
    # GetNodeNumChildren(TkHandle) -> int : resolve node, return SoA[mgr+0x78]+0 & 0x7fffffff.
    # numChildren field is the child-count read by MarkSelfOrDescendentsAABBDirty's loop bound.
    # Absent (inlined) in 1.13 and 1.09.1 - no standalone getter emitted there.
    ("Engine::GetNodeNumChildren", "1.24", 0x140F70F60, "0x78"),
    ("Engine::GetNodeNumChildren", "1.38", 0x141128A40, "0x78"),

    # ShiftAllTransformsForNode(TkHandle, cTkVector3 const&) : resolve node, add the vec4 to the
    # two transform SoA rows at mgr+0x58 and mgr+0x50 (offset +0x30, stride 0x40), then call
    # MarkSelfOrAncestorTransformDirtyRecurse + MarkSelfOrDescendentsAABBDirty.  Body byte-identical
    # across 1.13/1.24/1.38.  1.09.1 (virtual-dispatch nodes) restructures it - not emitted.
    ("Engine::ShiftAllTransformsForNode", "1.13", 0x140DA7210, "+ 0x50"),
    ("Engine::ShiftAllTransformsForNode", "1.24", 0x140F713F0, "+ 0x50"),
    ("Engine::ShiftAllTransformsForNode", "1.38", 0x141128EE0, "+ 0x50"),
]

UNRESOLVED = {
    "Engine::GetNodeNumChildren":
        "found 1.24/1.38; in 1.13 and 1.09.1 the SoA+0x78 child-count getter is not "
        "emitted as a standalone function (inlined at call sites)",
    "Engine::ShiftAllTransformsForNode":
        "found 1.13/1.24/1.38; 1.09.1 uses virtual-dispatch scene nodes and this "
        "transform-shift helper is inlined/restructured, no matching standalone body",
    "Engine::GetNodeParent":
        "parent TkHandle is stored inline at node SoA (mgr+0x78)+4 and read directly at "
        "every call site; no standalone getter exists in any of the four builds (only a "
        "first-child getter reading SoA+8 is emitted). Inlined.",
    "Engine::GetNodeName":
        "1.13/1.24/1.38 already resolved; 1.09.1 slot only. In 1.09.1 the node name is not "
        "a direct field read (as in 1.38, node+0x20 SSO string) - it goes through a vtable "
        "getter with no distinctive string, could not be isolated with two signals",
    "Engine::GetResourceHandleForNode":
        "no single-handle TkResHandle getter matched: node resource is reached via vtable "
        "getters that take extra params, and no resolver-caller returns a bare resource "
        "handle read from a node field; not isolated with two signals",
    "Engine::SetMaterialUniformArray":
        "no type-4 material float-array wrapper present. The material cluster only has "
        "single-uniform (vec4) wrappers (e.g. 1.38 FUN_141127320/3e0 -> cEgMaterialResource "
        "SetUniform) and multi-shader default variants; the array wrapper is inlined into "
        "its two callers",
    "Engine::GetRenderBufferTexture":
        "callee cEgRendererBase::GetRenderBufferTexture is not mapped in any legacy build "
        "and none of the modern callers (cTk2dImage::Render, cTkHmdOpenVR::*) are mapped; "
        "no string marker; could not disambiguate from sibling texture getters with 2 signals",
    "Engine::SetOption":
        "only marker is the 'Invalid param for EgSetOption' debug string, which is stripped "
        "from all four release builds (confirmed absent via string index); no other anchor",
    "Engine::AddResource":
        "no modern signature/callees/callers/strings in target_hints; nothing to fingerprint",
}


def main():
    functions = {}
    for name, build, va, marker in CANDIDATES:
        b = Binary(build)
        row = b.function_at(va)
        if row is None:
            log(f"SKIP {name} {build} {va:#x}: not a function start")
            continue
        decomp = row[3] or ""
        if marker not in decomp:
            log(f"SKIP {name} {build} {va:#x}: marker {marker!r} not in body")
            continue
        log(f"OK   {name} {build} {va:#x} ({row[0]}, size {row[2]})")
        functions.setdefault(name, {})[build] = f"{va:#x}".upper().replace("0X", "0x")

    out = {"functions": functions, "unresolved": UNRESOLVED}
    print(json.dumps(out))


if __name__ == "__main__":
    main()
