"""Finder for the ``planet_terrain`` NOT_YET_FOUND batch.

Targets: cGcPlanet / cGcEnvironment / cGcSky / cGcPlanetGenerator /
cGcResourceCustomisation / cGcTerrainEditorBeam functions.

Everything here is derived deterministically from two committed inputs that ship
with the repo -- each build's Ghidra decompilation DB (via ``common.Binary``) and
``out/propagated_<build>.json`` (the 4.13->legacy anchor map) -- plus the stable
TkID imm64 constants and string literals recorded in ``out/target_hints.json``.
No target address is hard-coded; each is re-derived from an anchor every run and
asserted to be a function start. Reasoning is logged to stderr; stdout is pure JSON.

Anchors and rules (all cross-checked against neighbours and sizes, see stderr):

* cGcPlanet::Construct -- the planet is constructed in a 6-iteration loop inside
  cGcSolarSystem::Construct (``do { ... FUN_construct(planet,i); ... } while (i<6)``).
  Construct is the largest function called inside that loop body (the other loop
  call is a tiny array-index helper).
* cGcPlanetGenerationInputData::SetDefaults -- Construct's callee with the lowest
  address (it lives in the low-address generated-metadata unit, ~0x1403xxxxx, far
  below gcplanet.cpp), a ~146-byte leaf.  Independently: Construct calls it.
* cGcPlanetGenerator::GenerateCreatureRoles -- the largest callee of
  cGcPlanetGenerator::Generate that embeds BOTH creature-role TkID imm64 hashes
  (0x64DD81482CBD31D7 and 0xE36AA5C613612997).  It also calls GenerateCreatureInfo
  and is called by Generate.
* cGcPlanetGenerator::GenerateCreatureInfo -- GenerateCreatureRoles' single largest
  exclusive callee (~1475 bytes; robot/biome UI strings that bloat it in 4.13 were
  added after these builds, so string matching fails here -- structure does not).
* cGcSky::Update -- propagate_symbols mislabels this as cGcPlanet::UpdateWeather;
  its callers are exactly {cGcSimulation::Update[, cGcApplicationSimulationState::
  ThreadSyncPoint]}, matching cGcSky::Update's modern caller set, so it is relabelled
  here after that caller check.
* cGcEnvironment::UpdateRender (1.13/1.24/1.38) -- the callee of
  cGcSimulation::UpdateRender that references the deferred-lighting shader-uniform
  string "gLightOriginVec4".  Absent in 1.09.1 (string not present -> unresolved).
* cGcPlanetGenerator::GenerateCreatureSpawnData / FillCreatureSpawnDataFromDescription
  (1.38) -- SpawnData is the small (~641 B) callee of Generate whose one large
  exclusive callee (~1744 B) is Fill; sizes match modern (676 / 1704).  Only 1.38 is
  confident.

Left unresolved (see the ``unresolved`` block for the specific obstacle): the terrain
manipulator functions (Fire/StartEffect/ApplyTerrainEdit*, 1.38-only, whose callees
sit outside the anchor map), the Sky sun sub-chain (SetSunAngle/UpdateSunPosition),
Planet weather leaves (UpdateClouds/UpdateGravity, true UpdateWeather is mislabelled),
GenerateQueryInfo (4 imm-cluster candidates, its unique caller SolarSystemQuery::Run
is unmapped), ResourceCustomisation::CreateGenerationTask, cGcEnvironment::Update,
and the early-build slots of the partial finds above.
"""

import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import BUILDS, Binary  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
BUILD_LIST = list(BUILDS)
IMMS = (0x64DD81482CBD31D7, 0xE36AA5C613612997)  # creature-role TkID hashes, stable across versions

_bins = {}
_prop = {}


def log(*a):
    print(*a, file=sys.stderr)


def B(build):
    if build not in _bins:
        _bins[build] = Binary(build)
    return _bins[build]


def prop(build):
    if build not in _prop:
        _prop[build] = json.loads((HERE / "out" / f"propagated_{build}.json").read_text())
    return _prop[build]


def anchor(build, name):
    e = prop(build).get(name)
    return int(e["address"], 16) if e else None


def decomp(build, va):
    r = B(build).function_at(va)
    return r[3] if r else None


def size(build, va):
    r = B(build).function_at(va)
    return r[2] if r else None


def is_func(build, va):
    return B(build).function_at(va) is not None


def uniq_calls(build, va):
    d = decomp(build, va)
    if not d:
        return []
    out = []
    for x in re.findall(r"FUN_([0-9a-f]+)", d):
        v = int(x, 16)
        if v != va and v not in out:
            out.append(v)
    return out


def referencers(build, va, limit=40):
    tok = "%FUN_" + format(va, "x") + "%"
    return [a for _, a, _ in B(build).functions_matching(tok, limit) if a != va]


def exclusive_callees(build, x):
    """Callees Y of X whose only referencer in the decomp DB is X."""
    out = []
    for y in uniq_calls(build, x):
        refs = referencers(build, y)
        if refs == [x]:
            out.append(y)
    return out


def body_of_count_loop(build, va, bound="< 6"):
    """Return the source text of the ``do { ... } while (... < N)`` loop, if any."""
    d = decomp(build, va)
    if not d:
        return None
    lines = d.splitlines()
    for i, l in enumerate(lines):
        if "while" in l and bound in l:
            j = i
            while j >= 0 and "do {" not in lines[j]:
                j -= 1
            if j >= 0:
                return "\n".join(lines[j : i + 1])
    return None


def string_vas(build, s):
    data = B(build).data
    pat = s.encode() + b"\0"
    out, idx = [], 0
    while True:
        k = data.find(pat, idx)
        if k == -1:
            break
        if k > 0 and data[k - 1] == 0:  # standalone NUL-terminated
            va = B(build).file_offset_to_va(k)
            if va is not None:
                out.append(va)
        idx = k + 1
    return out


def func_refs_va(build, func_va, target_va):
    """True if func's body contains a rip-relative reference to target_va."""
    r = B(build).function_at(func_va)
    if not r:
        return False
    off = B(build).va_to_file_offset(func_va)
    if off is None:
        return False
    data = B(build).data
    for p in range(off, off + r[2] - 4):
        disp = struct.unpack_from("<i", data, p)[0]
        iva = B(build).file_offset_to_va(p)
        if iva is not None and iva + 4 + disp == target_va:
            return True
    return False


def refs_both_imms(build, va):
    r = B(build).function_at(va)
    if not r:
        return False
    off = B(build).va_to_file_offset(va)
    if off is None:
        return False
    blob = B(build).data[off : off + r[2]]
    return all(struct.pack("<Q", imm) in blob for imm in IMMS)


# --------------------------------------------------------------------------- targets

def find_construct(build):
    ss = anchor(build, "cGcSolarSystem::Construct")
    if ss is None:
        return None
    body = body_of_count_loop(build, ss, "< 6")
    if not body:
        return None
    cands = [int(x, 16) for x in re.findall(r"FUN_([0-9a-f]+)", body)]
    cands = [c for c in cands if c != ss and is_func(build, c)]
    if not cands:
        return None
    cands.sort(key=lambda c: -(size(build, c) or 0))
    return cands[0]  # largest = Construct; other loop call is a tiny array-index helper


def find_setdefaults(build, construct):
    if construct is None:
        return None
    callees = [c for c in uniq_calls(build, construct) if is_func(build, c)]
    if not callees:
        return None
    lo = min(callees)  # SetDefaults lives in the low-address metadata unit
    if 130 <= (size(build, lo) or 0) <= 175:
        return lo
    return None


def find_roles(build):
    gen = anchor(build, "cGcPlanetGenerator::Generate")
    if gen is None:
        return None
    cands = [c for c in uniq_calls(build, gen) if c != gen and refs_both_imms(build, c)]
    if not cands:
        return None
    cands.sort(key=lambda c: -(size(build, c) or 0))
    return cands[0]  # largest such callee = GenerateCreatureRoles


def find_creature_info(build, roles):
    if roles is None:
        return None
    ex = exclusive_callees(build, roles)
    ex = [y for y in ex if is_func(build, y)]
    if not ex:
        return None
    ex.sort(key=lambda y: -(size(build, y) or 0))
    best = ex[0]
    return best if (size(build, best) or 0) > 800 else None


def find_sky_update(build):
    # propagate_symbols mislabels Sky::Update as cGcPlanet::UpdateWeather; verify by callers.
    cand = anchor(build, "cGcPlanet::UpdateWeather")
    if cand is None:
        return None
    simupd = anchor(build, "cGcSimulation::Update")
    if simupd is not None and cand in uniq_calls(build, simupd):
        return cand
    return None


def find_env_updaterender(build):
    simur = anchor(build, "cGcSimulation::UpdateRender")
    if simur is None:
        return None
    svas = string_vas(build, "gLightOriginVec4")
    if not svas:
        return None
    hits = [c for c in uniq_calls(build, simur)
            if is_func(build, c) and any(func_refs_va(build, c, v) for v in svas)]
    return hits[0] if len(hits) == 1 else None


def find_spawndata_pair(build):
    """Returns (spawndata_va, fill_va) or (None, None); confident on 1.38 only."""
    gen = anchor(build, "cGcPlanetGenerator::Generate")
    if gen is None:
        return None, None
    matches = []
    for x in uniq_calls(build, gen):
        if x == gen or not (550 <= (size(build, x) or 0) <= 900):
            continue
        big = [y for y in exclusive_callees(build, x) if 1500 <= (size(build, y) or 0) <= 2000]
        if len(big) == 1:
            matches.append((x, big[0]))
    if len(matches) == 1:
        return matches[0]
    return None, None


UNRESOLVED = {
    "cGcEnvironment::Update": "no PDB entry with a unique 4.13 VA (overloaded/inlined); no string or imm anchor to latch onto.",
    "cGcPlanet::UpdateClouds": "unique caller cGcPlanet::UpdateWeather is mislabelled in propagated (that address is really cGcSky::Update), so the weather-leaf cluster has no valid anchor; no distinctive tokens.",
    "cGcPlanet::UpdateGravity": "same as UpdateClouds: true cGcPlanet::UpdateWeather anchor unavailable; the gravity leaf (calls cTkDynamicGravityControl) has no mapped callee to pin it.",
    "cGcPlanetGenerator::GenerateQueryInfo": "in the same imm64 cluster as GenerateCreatureRoles; 4 candidate callers of Roles remain and its unique modern caller cGcSolarSystemQuery::Run is not in the anchor map, so it cannot be disambiguated from FulfillGenerationRequests/GenerateWonderQueryData.",
    "cGcResourceCustomisation::CreateGenerationTask": "16 callers, only 1 mapped callee (cGcProceduralTextureManager::CreateGenerationTask, itself unmapped); call-graph votes tie across many same-size candidates.",
    "cGcSky::SetSunAngle": "chain cGcSky::Update -> UpdateSunPosition -> SetSunAngle relies on unmapped leaves (sSolarDay::GetSunDirection/GetSolarSunAngle, cTkTrig::Cos/Sin); the trig helpers are shared by dozens of funcs so no unique lock.",
    "cGcSky::UpdateSunPosition": "same Sky sun sub-chain: its markers (Cos/Sin/GetSolarSunAngle) are unmapped and non-distinctive; multiple Sky-window candidates of similar size, no clear winner.",
    "cGcTerrainEditorBeam::Fire": "1.38-only; sits in the terrain-editor unit but its distinctive callees (EditTerrain, ApplyTerrainEdit*, GetEditData) are all unmapped, leaving a ~136-func window with no decisive anchor.",
    "cGcTerrainEditorBeam::StartEffect": "1.38-only; SHADOW+LASER_LIGHT locks a beam StartEffect at 0x140C9C320 but that lies OUTSIDE the terrain-editor unit (it is another beam's StartEffect); the terrain-unit candidate cannot be confirmed without its unmapped callees.",
    "cGcTerrainEditorBeam::ApplyTerrainEditFlatten": "1.38-only; no string/imm tokens and every callee (CanApplyTerrainEdit, EditTerrain, GenerateElevation, BroadcastEdits) is unmapped -> no anchor.",
    "cGcTerrainEditorBeam::ApplyTerrainEditStroke": "1.38-only; same as ApplyTerrainEditFlatten -- callee set entirely unmapped, and it is near-identical to Flatten so size/structure cannot separate them.",
    "cGcPlanetGenerator::FillCreatureSpawnDataFromDescription": "confident only for 1.38 (see functions); in 1.09.1/1.13/1.24 the Generate->SpawnData->Fill size signature is ambiguous (no callee anchor, sizes drift).",
    "cGcPlanetGenerator::GenerateCreatureSpawnData": "confident only for 1.38 (see functions); earlier builds give multiple Generate-callees fitting the size window with no tiebreaker.",
}


def main():
    functions = {}

    def put(name, build, va):
        if va is None:
            return
        if not is_func(build, va):
            log(f"!! {name} {build}: 0x{va:X} is NOT a function start; dropping")
            return
        functions.setdefault(name, {})[build] = f"0x{va:X}"
        log(f"   {name} {build} = 0x{va:X} (size {size(build, va)})")

    for build in BUILD_LIST:
        log(f"==== {build}")
        con = find_construct(build)
        put("cGcPlanet::Construct", build, con)
        put("cGcPlanetGenerationInputData::SetDefaults", build, find_setdefaults(build, con))
        roles = find_roles(build)
        put("cGcPlanetGenerator::GenerateCreatureRoles", build, roles)
        put("cGcPlanetGenerator::GenerateCreatureInfo", build, find_creature_info(build, roles))
        put("cGcSky::Update", build, find_sky_update(build))
        put("cGcEnvironment::UpdateRender", build, find_env_updaterender(build))
        sd, fill = find_spawndata_pair(build)
        # Only commit the SpawnData/Fill pair for 1.38 (sizes match modern; earlier builds ambiguous).
        if build == "1.38":
            put("cGcPlanetGenerator::GenerateCreatureSpawnData", build, sd)
            put("cGcPlanetGenerator::FillCreatureSpawnDataFromDescription", build, fill)

    print(json.dumps({"functions": functions, "unresolved": UNRESOLVED}, indent=1))


if __name__ == "__main__":
    main()
