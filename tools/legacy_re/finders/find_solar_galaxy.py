"""Finder for the "solar_galaxy" batch: cGcSolarSystem, galaxy attribute/voxel/star
classification, and name-generator functions.

Method (all derivations are self-contained: they use only each legacy build's own
Ghidra function set + call graph + imm64 fingerprints, anchored on functions already
mapped in nmspy/data/offsets.json and tools/legacy_re/out/propagated_<build>.json).
The Ghidra DBs are unsymbolised (FUN_<addr>); calls are recovered from raw E8/E9
displacements by propagate_symbols.Side, exactly as the propagation pass does.

Every emitted address rests on >=2 independent structural signals; anything that could
not be pinned that way is reported as unresolved rather than guessed. Reasoning is
logged to stderr; stdout is a single JSON object.

    python finders/find_solar_galaxy.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import propagate_symbols as ps  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
OFFSETS = HERE.parents[1] / "nmspy" / "data" / "offsets.json"
BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]

# TkID FNV hash embedded (as a mov r64, imm64) by both ClassifyStarKeyAttributes and
# GalaxyVoxelGenerator::Populate. Stable across every build.
IMM_STARKEY = 0x1BD11BDAA9FC1A22

TARGETS = [
    "SolarQueryResult::ComputeLightyearDistanceBetweenSolarSystems",
    "cGcGalaxyAttributeGenerator::ClassifyStarKeyAttributes",
    "cGcGalaxyAttributeGenerator::ClassifyStarSystem",
    "cGcGalaxyAttributeGenerator::ClassifyVoxel",
    "cGcGalaxyAttributesAtAddress::Classify",
    "cGcGalaxyStarAttributesData::SetDefaults",
    "cGcGalaxyVoxelAttributesData::SetDefaults",
    "cGcGalaxyVoxelGenerator::Populate",
    "cGcNameGenerator::GeneratePlanetName",
    "cGcSolarSystem::OnEnterPlanetOrbit",
    "cGcSolarSystem::OnLeavePlanetOrbit",
    "cGcSolarSystem::Update",
    "cGcSolarSystem::cGcSolarSystem",
    "cGcSolarSystemGenerator::GenerateBasics",
    "cGcSolarSystemGenerator::GeneratePlanetBiomes",
    "cGcSolarSystemGenerator::GeneratePlanetPositions",
    "cGcSolarSystemGenerator::GenerateQueryInfo",
    "cGcSolarSystemQuery::Run",
]

def log(build, msg):
    print(f"[{build}] {msg}", file=sys.stderr)


def anchor_map(build):
    """modern-name -> legacy address, from propagated_<build>.json + curated offsets."""
    a = {}
    prop = json.loads((HERE / "out" / f"propagated_{build}.json").read_text())
    for name, v in prop.items():
        try:
            a[name] = int(v["address"], 16)
        except (KeyError, ValueError):
            pass
    offs = json.loads(OFFSETS.read_text())["functions"]
    for name, e in offs.items():
        addr = e.get(build) if isinstance(e, dict) else None
        if isinstance(addr, str) and addr.startswith("0x"):
            a[name] = int(addr, 16)
    return a


def solve_build(build, found, unresolved):
    side = ps.load_side_build(build)
    size = {f[0]: f[1] for f in side.functions}
    starts = set(size)
    A = anchor_map(build)
    mapped = set(A.values())

    def ce(x):
        return side.callees.get(x, set())

    def cr(x):
        return side.callers.get(x, set())

    def imm_funcs(imm):
        return {k for k, toks in side.prints.items() if ("imm", imm) in toks}

    def commit(name, addr, why):
        if addr is None or addr not in starts:
            return None
        found.setdefault(name, {})[build] = f"0x{addr:X}"
        log(build, f"{name} = 0x{addr:X} (size {size.get(addr)}) <- {why}")
        return addr

    # ---- galaxy-attribute cluster --------------------------------------------
    # Anchor on the stable imm64 hash and on cGcSolarSystem::PollToPrepare (mapped in
    # every build). Two of the three imm-hash functions are ClassifyStarKeyAttributes
    # and GcGalaxyVoxelGenerator::Populate; the modern call chain is
    #   PollToPrepare -> AttributesAtAddress::Classify -> {ClassifyStarSystem, ClassifyVoxel}
    #   ClassifyStarSystem -> ClassifyStarKeyAttributes(+imm) -> ...
    #   Populate -> ClassifyStarKeyAttributes/ClassifyVoxel(+imm)
    # Solve the whole cluster at once by finding the single (starkey, classify,
    # starsystem, voxel) tuple consistent with all of those edges.
    cluster = imm_funcs(IMM_STARKEY)
    populate = max(cluster, key=lambda x: size.get(x, 0)) if cluster else None
    if populate is not None and size.get(populate, 0) > 4000:
        commit("cGcGalaxyVoxelGenerator::Populate", populate,
               f"largest of {len(cluster)} funcs referencing imm {IMM_STARKEY:#x}")
    else:
        populate = None

    ptp = A.get("cGcSolarSystem::PollToPrepare")
    tuples = []
    if populate is not None and ptp is not None:
        for sk in cluster - {populate}:
            for cl in ce(ptp) - mapped:                # Classify candidate
                ss_set = ce(cl) & cr(sk)               # ClassifyStarSystem: calls starkey
                vox = [v for v in ce(cl) & ce(populate) & ce(sk) if v not in mapped]
                if ss_set and len(vox) == 1:
                    for ss in ss_set:
                        tuples.append((sk, cl, ss, vox[0]))
    if len(tuples) == 1:
        starkey, classify, starsystem, voxel = tuples[0]
        commit("cGcGalaxyAttributeGenerator::ClassifyStarKeyAttributes", starkey,
               "imm-cluster member reached via PollToPrepare->Classify->StarSystem")
        commit("cGcGalaxyAttributesAtAddress::Classify", classify,
               "callee of PollToPrepare that calls both ClassifyStarSystem and "
               "ClassifyVoxel")
        commit("cGcGalaxyAttributeGenerator::ClassifyStarSystem", starsystem,
               "callee of Classify that calls ClassifyStarKeyAttributes")
        commit("cGcGalaxyAttributeGenerator::ClassifyVoxel", voxel,
               "unique callee shared by ClassifyStarKeyAttributes, Populate and Classify")
        # StarAttributesData::SetDefaults: the leaf (call-less) callee of
        # ClassifyStarSystem other than ClassifyStarKeyAttributes.
        sd = [c for c in ce(starsystem) if c != starkey and len(ce(c)) == 0]
        if len(sd) == 1:
            commit("cGcGalaxyStarAttributesData::SetDefaults", sd[0],
                   "leaf callee of ClassifyStarSystem (the other being StarKeyAttributes)")
    else:
        log(build, f"galaxy-attribute cluster not uniquely resolved "
                   f"({len(tuples)} candidate tuples)")

    # ---- name generator ------------------------------------------------------
    mk = A.get("cGcMarkovAssembler::Assemble")
    tr = A.get("cTkLanguageManagerBase::Translate")
    pg = A.get("cGcPlanetGenerator::Generate")
    if mk and tr and pg:
        cand = [c for c in cr(mk) & cr(tr) if c not in mapped and c in ce(pg)]
        if len(cand) == 1:
            commit("cGcNameGenerator::GeneratePlanetName", cand[0],
                   "caller of MarkovAssembler::Assemble & LanguageManagerBase::Translate "
                   "that is itself called by cGcPlanetGenerator::Generate")

    # ---- cGcSolarSystem constructor ------------------------------------------
    ssd = A.get("cGcSolarSystemData::SetDefaults")
    simctor = A.get("cGcSimulation::Construct")
    if ssd and simctor:
        cand = [c for c in cr(ssd) & ce(simctor) if c not in mapped]
        if len(cand) == 1:
            commit("cGcSolarSystem::cGcSolarSystem", cand[0],
                   "caller of cGcSolarSystemData::SetDefaults that cGcSimulation::"
                   "Construct calls")

    # ---- cGcSolarSystem::Update ----------------------------------------------
    # The one gcsolarsystem.cpp-TU function whose sole caller is cGcSimulation::Update.
    simupd = A.get("cGcSimulation::Update")
    tu_anchors = [A[n] for n in ("cGcSolarSystem::Construct",
                                 "cGcSolarSystem::PollToPrepare",
                                 "cGcSolarSystem::UpdateRender",
                                 "cGcSolarSystem::Generate",
                                 "cGcSolarSystem::PollPostPlanetGeneration") if n in A]
    if simupd and len(tu_anchors) >= 3:
        lo, hi = min(tu_anchors), max(tu_anchors)
        cand = [c for c in ce(simupd)
                if c not in mapped and cr(c) == {simupd} and lo <= c <= hi]
        if len(cand) == 1:
            commit("cGcSolarSystem::Update", cand[0],
                   "sole callee-of-Simulation::Update inside the gcsolarsystem.cpp TU "
                   f"span [{lo:#x},{hi:#x}]")

    return side


def main():
    found = {}
    for build in BUILDS:
        try:
            solve_build(build, found, None)
        except Exception as e:  # a missing DB/exe should not abort the whole run
            log(build, f"SKIP ({e})")

    unresolved = {}
    reasons = {
        "SolarQueryResult::ComputeLightyearDistanceBetweenSolarSystems":
            "small (542B) leaf reached only from unmapped cGcGalaxyMap::Data methods; "
            "no distinctive string/imm/anchored callee to pin it in any build",
        "cGcGalaxyVoxelAttributesData::SetDefaults":
            "76-byte metadata SetDefaults, inlined at every call site (never a direct "
            "callee of Populate/ClassifyStarKeyAttributes in the legacy call graph)",
        "cGcSolarSystem::OnEnterPlanetOrbit":
            "its distinctive callees (FadeNodeUpdater::GetInstance, "
            "PersistentInteractionsManager::LoadGalacticAddressBuffers, "
            "GetPlayerSolarSystemInstance) and 0x9A94.. imm are all unmapped/absent "
            "in the legacy builds",
        "cGcSolarSystem::OnLeavePlanetOrbit":
            "same as OnEnterPlanetOrbit: no mapped distinctive callee and the second "
            "caller (cGcPlayerRespawn::UpdateSolarSystem) is unmapped",
        "cGcSolarSystemGenerator::GenerateBasics":
            "inlined into cGcSolarSystemGenerator::Generate in 1.38 (Generate calls "
            "ClassifyStarKeyAttributes directly); no standalone anchored signal",
        "cGcSolarSystemGenerator::GeneratePlanetBiomes":
            "sub-generator with no mapped distinctive callee; cannot be separated from "
            "its siblings among Generate's in-TU callees with two signals",
        "cGcSolarSystemGenerator::GeneratePlanetPositions":
            "callees (cTkFibonacciSphere::Generate, GetRegionRadiusForSize, trig) are "
            "unmapped, so it cannot be distinguished from its sibling sub-generators",
        "cGcSolarSystemGenerator::GenerateQueryInfo":
            "inlined into cGcSolarSystemGenerator::Generate in 1.38 (Generate is the "
            "only generator-TU caller of SolarSystemData::SetDefaults)",
        "cGcSolarSystemQuery::Run":
            "calls Classify/GenerateQueryInfo that are inlined here, and none of its "
            "callers (SolarInfoPanel::Update, ...) are mapped",
    }
    for t in TARGETS:
        if t not in found:
            unresolved[t] = reasons.get(t, "no two-signal derivation available")

    json.dump({"functions": found, "unresolved": unresolved}, sys.stdout)
    print()


if __name__ == "__main__":
    main()
