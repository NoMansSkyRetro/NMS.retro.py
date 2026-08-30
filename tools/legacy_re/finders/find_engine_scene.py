"""Locate Engine:: scene-graph free functions across the four legacy builds.

Batch: engine_scene. These are static/namespace functions from egmain.cpp. They
cluster in two regions of the engine compilation unit:

  * a "node" region around Engine::GetNodeAbsoluteTransMatrix, and
  * a dense "resource / node-add" region around Engine::Initialise ..
    Engine::AddCameraNode.

Two anchors are already mapped and drive every derivation here:

  resolver = Engine::GetNodeName<1>(TkHandle)   (propagated as ??$GetNodeName@$00@...)
      the TkHandle -> cEgSceneNodeData* resolver. Every node accessor calls it as
      FUN_resolver(global_scene_mgr, handle). NOTE: despite its mangled name this
      function returns the *node pointer*, not a name; it is the internal resolver.
  gdr = cTkResourceManager::GetDefaultResource
      every resource/material/texture wrapper resolves its TkResHandle through it.

Both addresses come from out/propagated_<build>.json (already-matched 4.13->legacy
pairs), so this script stays self-contained and deterministic.

Resolved here, each by a distinctive code signature that reproduces in all builds:

  Engine::SetMaterialSampler  the cluster function that resolves TWO resHandles,
      checks resource type 4 (material) AND 7 (sampler), and calls SetSampler
      directly on the resolved material returning a masked bool (its twin, +0x100
      bytes on, routes the same call through the engine object and returns void ->
      that is the render-thread variant, excluded).
  Engine::GetNodeName        single-handle node accessor returning the node name
      string (node+0x20), falling back to a static empty-string global when the
      handle does not resolve.
  Engine::GetNodeType        single-handle node accessor returning the node type,
      read as a short out of the scene-manager SoA array at mgr+0x90. Corroborated
      by the imposter helper that compares that exact slot against type constant 3.
  Engine::GetTexture         thin type-7 (texture) resource wrapper that returns a
      pointer into the resolved texture resource and has no callee but GetDefaultResource.

Everything else in the batch is reported unresolved with the reason: the material
uniform-array setter and several node getters (parent / num-children /
resource-handle) do not appear as standalone functions in these older builds (they
are inlined at every call site), and Engine::SetOption's only distinctive marker
(the "Invalid param for EgSetOption" debug string) is stripped from these release
builds.

    python finders/find_engine_scene.py        # prints one JSON object to stdout
"""

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "out"
sys.path.insert(0, str(HERE.parent))  # common.py lives one level up

from common import Binary

BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]

# Engine cluster bounds (dense resource / node-add region) per build, taken from the
# already-mapped anchors Engine::Initialise .. just past Engine::AddCameraNode.
CLUSTER = {
    "1.09.1": (0x140C28000, 0x140C2F000),
    "1.13": (0x140DA2000, 0x140DA9000),
    "1.24": (0x140F6B000, 0x140F73000),
    "1.38": (0x141123000, 0x14112B000),
}
# Wider "node region" bound (accessors sit near GetModelNode / AddGroupNode).
NODE_REGION = {
    "1.09.1": (0x140C2C000, 0x140C2F000),
    "1.13": (0x140DA6000, 0x140DA9000),
    "1.24": (0x140F70000, 0x140F73000),
    "1.38": (0x141128000, 0x14112B000),
}


def log(*a):
    print(*a, file=sys.stderr)


def anchor(build, key):
    d = json.loads((OUT / f"propagated_{build}.json").read_text())
    if key == "resolver":
        for k, v in d.items():
            if k.startswith("??$GetNodeName@"):
                return int(v["address"], 16)
    if key == "gdr":
        v = d.get("cTkResourceManager::GetDefaultResource")
        if v:
            return int(v["address"], 16)
    return None


def cluster_callers(b, callee, lo, hi):
    """Functions in [lo,hi) whose decomp calls FUN_<callee>."""
    rows = b.db.execute(
        "SELECT address,size,raw_decomp FROM decompilations "
        "WHERE raw_decomp LIKE ? AND address BETWEEN ? AND ? ORDER BY address",
        (f"%FUN_{callee:x}%", lo, hi),
    ).fetchall()
    return rows


def find_set_material_sampler(b, gdr, lo, hi):
    cands = []
    for a, s, dec in cluster_callers(b, gdr, lo, hi):
        if "== 4)" in dec and "== 7)" in dec and "0xffffffffffffff00" in dec:
            cands.append((a, s))
    # The direct-bool material sampler is unique; its render twin returns void
    # (no masked-bool return) and is filtered out above.
    if len(cands) == 1:
        return cands[0][0], f"type-4&7 material sampler returning masked bool, size {cands[0][1]}"
    return None, f"ambiguous ({len(cands)} candidates: {[hex(a) for a,_ in cands]})"


def find_get_node_name(b, resolver, lo, hi):
    cands = []
    for a, s, dec in cluster_callers(b, resolver, lo, hi):
        nargs = dec.split(")")[0].count("param_")
        # single handle arg, returns a pointer, reads node+0x20, falls back to a
        # static empty-string global (&DAT_...) when the handle does not resolve.
        if (
            nargs == 1
            and "+ 0x20)" in dec
            and re.search(r"return \(undefined8 \*\)&DAT_", dec)
            and "void " not in dec.split("(")[0]
        ):
            cands.append((a, s))
    if len(cands) == 1:
        return cands[0][0], f"node-name accessor (node+0x20 / empty-string default), size {cands[0][1]}"
    return None, f"ambiguous ({len(cands)} candidates: {[hex(a) for a,_ in cands]})"


def find_get_node_type(b, resolver, lo, hi):
    cands = []
    for a, s, dec in cluster_callers(b, resolver, lo, hi):
        nargs = dec.split(")")[0].count("param_")
        # single handle arg, returns (int) short read from a scene-mgr SoA array
        # (mgr+0x90 in 1.13+, mgr+0x88 in 1.09.1 - offset drifts across versions).
        if (
            nargs == 1
            and dec.split("(")[0].strip().startswith("int ")
            and re.search(
                r"return \(int\)\*\(short \*\)\(\*\(longlong \*\)\(\w+ \+ 0x[0-9a-f]+\)", dec
            )
        ):
            cands.append((a, s))
    if len(cands) == 1:
        return cands[0][0], f"node-type accessor (short from scene-mgr SoA), size {cands[0][1]}"
    return None, f"ambiguous ({len(cands)} candidates: {[hex(a) for a,_ in cands]})"


def find_add_nodes(b, resolver, gdr, lo, hi):
    rows = b.db.execute(
        "SELECT address,size,raw_decomp FROM decompilations "
        "WHERE raw_decomp LIKE ? AND raw_decomp LIKE ? AND address BETWEEN ? AND ? ORDER BY address",
        (f"%FUN_{resolver:x}%", f"%FUN_{gdr:x}%", lo, hi),
    ).fetchall()
    cands = []
    for a, s, dec in rows:
        sig = dec.split("{")[0].replace("\n", " ")
        args = sig.split("(")[1].split(")")[0]
        # (TkHandle node, TkResHandle resource) -> TkHandle. Resolves the node
        # (must be node type 2) and the resource (must be resource type 3), then
        # calls the cEgSceneManager::AddNodes worker. Two args, non-void.
        if (
            args.count("param_") == 2
            and re.search(r",int param_2\)", sig)
            and "!= 3)" in dec
            and "!= 2)" in dec
            and not sig.strip().startswith("void")
        ):
            cands.append((a, s))
    if len(cands) == 1:
        return cands[0][0], f"node+resource wrapper (type 2 / type 3) calling scene AddNodes, size {cands[0][1]}"
    return None, f"ambiguous ({len(cands)} candidates: {[hex(a) for a,_ in cands]})"


def find_get_texture(b, gdr, lo, hi):
    cands = []
    for a, s, dec in cluster_callers(b, gdr, lo, hi):
        if "== 7)" not in dec:
            continue
        nargs = dec.split(")")[0].count("param_")
        # single resHandle arg; only callee is GetDefaultResource; returns a pointer
        # INTO the resolved texture resource (lVar + const), i.e. the embedded texture.
        other_calls = set(re.findall(r"FUN_([0-9a-f]+)\(", dec)) - {
            f"{gdr:x}",
            f"{a:x}",
        }
        if nargs == 1 and not other_calls and re.search(r"return \w+ \+ 0x[0-9a-f]+;", dec):
            cands.append((a, s))
    if len(cands) == 1:
        return cands[0][0], f"type-7 texture wrapper returning embedded texture pointer, size {cands[0][1]}"
    return None, f"ambiguous ({len(cands)} candidates: {[hex(a) for a,_ in cands]})"


UNRESOLVED = {
    "Engine::AddResource": "no modern signature/callees in hints; no distinctive legacy signature found",
    "Engine::GetNodeNumChildren": "no standalone single-handle getter matches; inlined at call sites in these builds",
    "Engine::GetNodeParent": "no standalone single-handle getter matches; inlined at call sites in these builds",
    "Engine::GetResourceHandleForNode": "only one ambiguous single-handle getter (mgr+0x78 SoA); one weak signal, not committed",
    "Engine::GetRenderBufferTexture": "render-buffer lookup wrapper not disambiguated from sibling texture getters with two signals",
    "Engine::SetMaterialUniformArray": "no type-4 float-array material wrapper present; inlined into its two callers in these builds",
    "Engine::SetOption": "only marker is the 'Invalid param for EgSetOption' debug string, stripped from these release builds",
    "Engine::ShiftAllTransformsForNode": "MarkSelfOrAncestorTransformDirtyRecurse/MarkSelfOrDescendentsAABBDirty callees unmapped in legacy; not isolated with two signals",
}


def main():
    functions = {}
    unresolved = dict(UNRESOLVED)

    # kind selects which callee anchor + address window the finder scans over.
    finders = [
        ("Engine::SetMaterialSampler", find_set_material_sampler, "gdr"),
        ("Engine::GetNodeName", find_get_node_name, "resolver"),
        ("Engine::GetNodeType", find_get_node_type, "resolver"),
        ("Engine::GetTexture", find_get_texture, "gdr"),
        ("Engine::AddNodes", find_add_nodes, "both"),
    ]

    for build in BUILDS:
        b = Binary(build)
        resolver = anchor(build, "resolver")
        gdr = anchor(build, "gdr")
        clo, chi = CLUSTER[build]
        nlo, nhi = NODE_REGION[build]
        log(f"=== {build}: resolver=0x{resolver:X} gdr=0x{gdr:X} ===")
        for name, fn, kind in finders:
            if kind == "both":
                addr, why = fn(b, resolver, gdr, clo, chi)
            else:
                callee = gdr if kind == "gdr" else resolver
                lo, hi = (clo, chi) if kind == "gdr" else (nlo, nhi)
                addr, why = fn(b, callee, lo, hi)
            if addr is None:
                log(f"  {name}: UNRESOLVED in {build}: {why}")
                continue
            row = b.function_at(addr)
            if row is None:
                log(f"  {name}: 0x{addr:X} not a function start; skipping")
                continue
            log(f"  {name}: 0x{addr:X}  ({why})")
            functions.setdefault(name, {})[build] = f"0x{addr:X}"

    # Any solid function that failed in every build should carry a reason too.
    for name, _, _ in finders:
        if name not in functions:
            unresolved.setdefault(name, "signature scan produced no unique match in any build")

    print(json.dumps({"functions": functions, "unresolved": unresolved}))


if __name__ == "__main__":
    main()
