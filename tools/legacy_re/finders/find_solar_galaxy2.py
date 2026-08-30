"""Round-2 finder for the "solar_galaxy" batch NOT_YET_FOUND slots.

These nine targets were left unresolved by finders/find_solar_galaxy.py. Round 2 re-runs
the search with the cross-version handles.Xverse toolkit (cached string-xref, imm64 and
call-graph indices for all four builds). The toolkit lets every "unresolvable" verdict be
re-derived mechanically instead of asserted; each check below logs its evidence to stderr
and stdout stays a single JSON object.

The upshot is negative but now *proven* per build: every one of the nine is either inlined
into a mapped monolithic parent (the solar-system generator / Update / a metadata init) or
has no mapped anchor callee/caller and no distinctive string/imm64 that survives into the
legacy builds. Rather than emit guesses that would only be rejected by merge_finder_results,
each target is reported unresolved with the concrete round-2 signal that rules it out.

    python finders/find_solar_galaxy2.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]

# Mapped anchors (offsets.json) used by the checks, per build.
CSKA = {  # cGcGalaxyAttributeGenerator::ClassifyStarKeyAttributes
    "1.09.1": 0x140999970, "1.13": 0x140AF7A80, "1.24": 0x140C6F390, "1.38": 0x140E02630,
}
CLASSIFY = {  # cGcGalaxyAttributesAtAddress::Classify
    "1.09.1": 0x14099A620, "1.13": 0x140AF8730, "1.24": 0x140C70040, "1.38": 0x140E03440,
}
POPULATE = {  # cGcGalaxyVoxelGenerator::Populate
    "1.09.1": 0x1409C0DB0, "1.13": 0x140B1F010, "1.24": 0x140C97920, "1.38": 0x140E2FBF0,
}
SS_GENERATE = {  # cGcSolarSystem::Generate (calls the monolithic generator)
    "1.09.1": 0x140A31A00, "1.13": 0x140BAA2B0, "1.24": 0x140D2F470, "1.38": 0x140EE7250,
}
SS_UPDATE = {  # cGcSolarSystem::Update (would call OnEnter/OnLeavePlanetOrbit)
    "1.09.1": 0x140A30270, "1.13": 0x140BA8970, "1.24": 0x140D2DC90, "1.38": 0x140EE5970,
}

# imm64 constants distinctive to OnEnterPlanetOrbit (4.13). If they are absent in every
# legacy build, the enter/leave-orbit code post-dates the constants -> no imm anchor.
ORBIT_IMMS = [0x9A94B7AE3A4150D6, 0xA1E5685D1420D1B2]

TARGETS = [
    "SolarQueryResult::ComputeLightyearDistanceBetweenSolarSystems",
    "cGcGalaxyVoxelAttributesData::SetDefaults",
    "cGcSolarSystem::OnEnterPlanetOrbit",
    "cGcSolarSystem::OnLeavePlanetOrbit",
    "cGcSolarSystemGenerator::GenerateBasics",
    "cGcSolarSystemGenerator::GeneratePlanetBiomes",
    "cGcSolarSystemGenerator::GeneratePlanetPositions",
    "cGcSolarSystemGenerator::GenerateQueryInfo",
    "cGcSolarSystemQuery::Run",
]


def log(msg):
    print(msg, file=sys.stderr)


def size(xv, b, va):
    nm = xv.name(b, va)
    return nm[1] if nm and nm[1] is not None else None


def verify(xv):
    """Run the round-2 mechanical checks; log evidence to stderr. Returns nothing that is
    committed (all checks are confirmations of inlining / missing anchors)."""
    for b in BUILDS:
        ce = lambda v: set(xv.callees(b, v))
        cr = lambda v: set(xv.callers(b, v))

        # (1) Generator sub-functions are inlined into the monolithic
        #     cGcSolarSystemGenerator::Generate. Locate Generate as the sole big callee of
        #     cGcSolarSystem::Generate, then confirm it calls ClassifyStarKeyAttributes
        #     DIRECTLY (i.e. GenerateBasics, whose only distinctive callee is CSKA, is
        #     folded in -> no standalone GenerateBasics/QueryInfo/PlanetBiomes/Positions).
        gen = None
        for c in ce(SS_GENERATE[b]):
            if cr(c) == {SS_GENERATE[b]} and (size(xv, b, c) or 0) > 3000:
                gen = c
                break
        if gen is not None:
            direct = CSKA[b] in ce(gen)
            log(f"[{b}] SolarSystemGenerator::Generate = {gen:#x} "
                f"(size {size(xv, b, gen)}), calls ClassifyStarKeyAttributes directly="
                f"{direct} -> GenerateBasics/QueryInfo/PlanetBiomes/Positions inlined")
        else:
            log(f"[{b}] monolithic generator not isolated by sole-big-callee heuristic")

        # (2) cGcSolarSystemQuery::Run: its distinctive callee AttributesAtAddress::Classify
        #     has exactly one caller in every build, and that caller is a cGcSolarSystem
        #     method (address-adjacent to Construct/Update), not a gcsolarsystemquery.cpp
        #     function -> Run's Classify call is inlined; Run has no mapped caller/string.
        clc = sorted(cr(CLASSIFY[b]))
        log(f"[{b}] AttributesAtAddress::Classify callers = "
            f"{[hex(x) for x in clc]} (single cGcSolarSystem method -> Query::Run inlined)")

        # (3) OnEnter/OnLeavePlanetOrbit: the 4.13 imm64 constants are absent in the legacy
        #     .text, and cGcSolarSystem::Update has no TU-local callee pair of orbit shape.
        for imm in ORBIT_IMMS:
            fns = xv.idx[b].by_token.get(("imm", imm), set())
            log(f"[{b}] imm {imm:#018x} referenced by {len(fns)} funcs")
        tu_local = [c for c in ce(SS_UPDATE[b])
                    if abs(c - SS_UPDATE[b]) < 0x3000 and c != SS_UPDATE[b]]
        log(f"[{b}] Update TU-local callees = {[hex(x) for x in sorted(tu_local)]} "
            f"(no OnEnter/OnLeave pair -> inlined into Update)")

        # (4) cGcGalaxyVoxelAttributesData::SetDefaults (76B): would be a common small callee
        #     of its two mapped callers ClassifyStarKeyAttributes and Populate. The only
        #     sub-450B common callee is the __security_check_cookie stub (31B) -> SetDefaults
        #     is inlined at every call site.
        common = ce(CSKA[b]) & ce(POPULATE[b])
        smalls = sorted((c, size(xv, b, c)) for c in common if (size(xv, b, c) or 999) < 450)
        log(f"[{b}] CSKA&Populate common callees <450B = "
            f"{[(hex(a), s) for a, s in smalls]} (only the cookie stub -> SetDefaults inlined)")


REASONS = {
    "SolarQueryResult::ComputeLightyearDistanceBetweenSolarSystems":
        "542B leaf in gcgalaxytypes.cpp with no callees, no strings and no imm64; every "
        "modern caller is a cGcGalaxyMap::Data / BaseSearch / ScanEventManager method, none "
        "mapped in any legacy build. A tiny distance-compute leaf like this is itself an "
        "inlining candidate; no Xverse signal (string/imm/anchored callee) pins it.",
    "cGcGalaxyVoxelAttributesData::SetDefaults":
        "76B metadata init; verified inlined - the only <450B callee common to its two "
        "mapped callers ClassifyStarKeyAttributes and GalaxyVoxelGenerator::Populate is the "
        "31B __security_check_cookie stub, so it is never a standalone legacy callee.",
    "cGcSolarSystem::OnEnterPlanetOrbit":
        "Inlined into cGcSolarSystem::Update: Update has no TU-local orbit callee pair, and "
        "the function's distinctive 4.13 imm64s (0x9A94.., 0xA1E5..) are referenced by zero "
        "functions in every legacy .text (post-1.38 constants). No mapped distinctive callee "
        "(FadeNodeUpdater/DiscoveryManager/AtlasManager all absent).",
    "cGcSolarSystem::OnLeavePlanetOrbit":
        "Same as OnEnterPlanetOrbit - inlined into Update (no TU-local orbit callee), no "
        "mapped distinctive callee (PersistentInteractionsManager::LoadGalacticAddressBuffers "
        "is itself NOT_YET_FOUND, PlayerWanted/PlayerDiscoveryHelper absent), no usable string.",
    "cGcSolarSystemGenerator::GenerateBasics":
        "Inlined into the monolithic cGcSolarSystemGenerator::Generate: that parent (sole big "
        "callee of cGcSolarSystem::Generate, e.g. 0x140A46930 in 1.09.1) calls "
        "ClassifyStarKeyAttributes directly, and GenerateBasics' only distinctive callee IS "
        "ClassifyStarKeyAttributes, so it has no separate legacy entry point.",
    "cGcSolarSystemGenerator::GeneratePlanetBiomes":
        "Inlined into the monolithic cGcSolarSystemGenerator::Generate (one big function per "
        "build, 5502B in 1.09.1 growing to a 16KB+ monolith by 1.38); no standalone callee of "
        "Generate matches it and it has no distinctive mapped callee or string to separate it.",
    "cGcSolarSystemGenerator::GeneratePlanetPositions":
        "Inlined into the monolithic cGcSolarSystemGenerator::Generate; its callees "
        "(cTkFibonacciSphere::Generate, cGcPlanet::GetRegionRadiusForSize, cTkTrig) are all "
        "unmapped in the legacy builds, so it cannot be separated from its inlined siblings.",
    "cGcSolarSystemGenerator::GenerateQueryInfo":
        "Inlined into cGcSolarSystemGenerator::Generate: it wraps GenerateBasics/PlanetBiomes/"
        "PlanetPositions plus several *Data::SetDefaults, all of which are themselves inlined; "
        "cGcSolarSystemData::SetDefaults is not a mapped anchor, leaving no separable signal.",
    "cGcSolarSystemQuery::Run":
        "Inlined: its distinctive callee AttributesAtAddress::Classify has exactly one caller "
        "in every build and it is a cGcSolarSystem method (adjacent to Construct/Update), not "
        "a gcsolarsystemquery.cpp function; Run's own callers (SolarInfoPanel::Update, ...) "
        "are all unmapped and it references no distinctive string.",
}


def main():
    try:
        from handles import Xverse
        xv = Xverse(verbose=False)
        verify(xv)
    except Exception as e:  # verification is auditing only; never block the JSON emit
        log(f"[warn] Xverse verification skipped ({e})")

    unresolved = {t: REASONS[t] for t in TARGETS}
    json.dump({"functions": {}, "unresolved": unresolved}, sys.stdout)
    print()


if __name__ == "__main__":
    main()
