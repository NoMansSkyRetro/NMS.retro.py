"""Finder for the "app_misc" catch-all batch.

Locates NOT_YET_FOUND functions for cGcApplication / cGcGameState extras,
cTkAudioManager / cTkSystem / cTkInputPort odds-and-ends, plus the NMS-Newton
GetRespawnReason hook.

Everything here is derived from anchors that are already mapped (offsets.json /
out/propagated_<build>.json), so re-running reproduces the addresses. Reasoning is
logged to stderr; stdout is a single JSON object per the hunt protocol.

Run from tools/legacy_re/:  python finders/find_app_misc.py
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import Binary  # noqa: E402

BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]
HERE = Path(__file__).resolve().parents[1]


def log(*a):
    print(*a, file=sys.stderr)


_bins = {}


def B(build):
    if build not in _bins:
        _bins[build] = Binary(build)
    return _bins[build]


_prop = {}


def prop(build):
    if build not in _prop:
        _prop[build] = json.loads((HERE / "out" / f"propagated_{build}.json").read_text())
    return _prop[build]


def anchor(build, name):
    """Legacy VA of an already-mapped function, from propagated_<build>.json."""
    row = prop(build).get(name)
    return int(row["address"], 16) if row else None


def callees(b, va):
    """Distinct FUN_ targets referenced in va's decomp, in first-seen order."""
    row = b.function_at(va)
    if not row:
        return []
    return [int(x, 16) for x in dict.fromkeys(re.findall(r"FUN_(14[0-9a-f]+)", row[3]))]


def callers(b, va):
    return [a for _n, a, _s in b.functions_matching(f"%FUN_{va:x}%", 120) if a != va]


functions = {}
unresolved = {}


def record(name, build, va):
    functions.setdefault(name, {})[build] = f"0x{va:X}"
    log(f"  [{name}] {build} = 0x{va:X}")


# ---------------------------------------------------------------------------
# cTkLanguageManagerBase::Load
#
# The curated 1.13/1.24 slots point at a 161-byte enum->name function that
# returns the language-name string literals ("USENGLISH", "POLISH",
# "LATINAMERAICANSPANISH" [sic], ...). It is the unique small function carrying
# the distinctive misspelled "LATINAMERAICANSPANISH" literal, and it sits next
# to cTkLanguageManagerBase::Translate in every build. Re-deriving it in all
# four builds reproduces the curated pair and fills 1.09.1 / 1.38.
# ---------------------------------------------------------------------------
def find_language_load():
    log("cTkLanguageManagerBase::Load: unique small fn returning language literals")
    for build in BUILDS:
        b = B(build)
        rows = b.db.execute(
            "SELECT address,size FROM decompilations "
            "WHERE raw_decomp LIKE '%\"LATINAMERAICANSPANISH\"%' "
            "AND raw_decomp LIKE '%\"USENGLISH\"%' AND size < 300"
        ).fetchall()
        if len(rows) == 1:
            record("cTkLanguageManagerBase::Load", build, rows[0][0])
        else:
            log(f"  {build}: expected 1 candidate, got {[hex(a) for a,_ in rows]}")


# ---------------------------------------------------------------------------
# cGcApplicationLocalLoadState::GetRespawnReason   (NMS-Newton hook)
#
# modern_callers = {cGcApplicationLocalLoadState::Update} only.
# The function is a small enum getter that reads the load-state flags at
# this+0x34/0x35/0x36 and returns a RespawnReason enum value; in 1.24/1.38 it
# also touches cGcUGCBasesManager::GetInstance. We take the sole-callee of the
# (mapped) Update whose decomp reads (param_1 + 0x34) and returns an int enum,
# with Update as its only caller. Unique in 1.13/1.24/1.38.
#
# 1.09.1 predates the respawn refactor: no Update-sole-callee matches this
# shape (the logic is inlined / differently structured), so it stays unresolved.
# ---------------------------------------------------------------------------
def find_respawn_reason():
    log("cGcApplicationLocalLoadState::GetRespawnReason: sole enum-getter callee of Update")
    for build in BUILDS:
        b = B(build)
        upd = anchor(build, "cGcApplicationLocalLoadState::Update")
        if upd is None:
            log(f"  {build}: Update anchor missing")
            continue
        hits = []
        for c in callees(b, upd):
            d = b.function_at(c)
            if not d or d[2] > 450:
                continue
            txt = d[3]
            if "(param_1 + 0x34)" not in txt:
                continue
            if not re.search(r"return (0x[0-9a-f]+|\d+);", txt):
                continue
            if callers(b, c) == [upd]:
                hits.append(c)
        if len(hits) == 1:
            record("cGcApplicationLocalLoadState::GetRespawnReason", build, hits[0])
        else:
            log(f"  {build}: {len(hits)} candidates {[hex(x) for x in hits]}")
            if build == "1.09.1":
                unresolved.setdefault(
                    "cGcApplicationLocalLoadState::GetRespawnReason",
                    "1.09.1: pre-respawn-refactor; no Update-sole-callee matches the "
                    "param+0x34 enum-getter shape (logic inlined/restructured). Found in "
                    "1.13/1.24/1.38.",
                )


# ---------------------------------------------------------------------------
# cGcRealityManager::GenerateProceduralTechnology
#
# modern_callers include cGcPurchaseableItem::SetupSpecific (mapped, all builds)
# and it calls cTkLanguageManagerBase::Translate (mapped, all builds). In every
# build there is exactly one large (>1500 byte) callee of SetupSpecific that
# itself calls Translate; its size is stable across versions (~3.7-3.9 KB).
# Two independent signals (mapped caller + mapped callee) plus cross-version
# consistency => committed for all four builds.
# ---------------------------------------------------------------------------
def find_generate_proc_tech():
    log("cGcRealityManager::GenerateProceduralTechnology: SetupSpecific->large callee calling Translate")
    for build in BUILDS:
        b = B(build)
        setup = anchor(build, "cGcPurchaseableItem::SetupSpecific")
        trans = anchor(build, "cTkLanguageManagerBase::Translate")
        if setup is None or trans is None:
            log(f"  {build}: anchor missing setup={setup} trans={trans}")
            continue
        hits = []
        for c in callees(b, setup):
            if c == setup:
                continue
            d = b.function_at(c)
            if not d or d[2] < 1500:
                continue
            if trans in callees(b, c):
                hits.append(c)
        if len(hits) == 1:
            record("cGcRealityManager::GenerateProceduralTechnology", build, hits[0])
        else:
            log(f"  {build}: {len(hits)} candidates {[hex(x) for x in hits]}")


def main():
    find_language_load()
    find_respawn_reason()
    find_generate_proc_tech()

    # --- Honest unresolved entries for the rest of the batch -----------------
    unresolved.setdefault(
        "cGcRealityManager::GenerateProceduralProduct",
        "Same reality unit as GenerateProceduralTechnology but two large self-"
        "recursive candidates per build (e.g. 1.38 0x140C7A080 sz5129 vs "
        "0x140C81640 sz16361) with conflicting signals (callee-overlap vs size); "
        "cannot disambiguate with two clean signals. No mapped caller available.",
    )
    unresolved.setdefault(
        "cGcApplication::Data::Data",
        "Nested cGcApplication::Data ctor. Modern caller cGcApplication::Construct "
        "is mapped but the legacy Construct calls only small helpers (no ~1.5KB "
        "manager-aggregating ctor); likely pre-refactor (managers built directly / "
        "via static init). Unique imm64 0xA3BD50BB894800A3 absent from legacy .text.",
    )
    unresolved.setdefault(
        "cGcGameState::cGcGameState",
        "Only anchor is caller cGcApplication::Data::Data (itself unresolved). "
        "gamestate unit located (LoadFromPersistentStorage/WriteStateToStorage "
        "literals) but the ctor cannot be singled out from sibling methods "
        "without a mapped neighbour; imm64 0xC4CEB9FE1A85EC53 absent from legacy.",
    )
    unresolved.setdefault(
        "cGcRealityManager::cGcRealityManager",
        "Sole modern caller is cGcApplication::Data::Data (unresolved). Reality "
        "unit identified but no mapped anchor isolates the ctor; imm64 anchor "
        "absent from legacy .text.",
    )
    unresolved.setdefault(
        "cGcSimulation::cGcSimulation",
        "Sole modern caller is cGcApplication::Data::Data (unresolved). "
        "cGcSimulation::Construct zone located (1.38 0x140C956A0) but the ctor "
        "vs Construct/other members cannot be split with a second signal.",
    )
    unresolved.setdefault(
        "cGcGameState::ComputeWarpCapability",
        "Only mapped anchor is callee cGcPlayerState::GetPrimaryItemForStat "
        "(shared by many functions); its callers (cGcGalaxyMap::Data solar fns) "
        "are unmapped, so no unique intersection. No distinctive strings/imm64.",
    )
    unresolved.setdefault(
        "cGcQuickActionMenu::TriggerAction",
        "1.09.1 only: quick-action-menu strings first appear in Foundation (1.1); "
        "the function does not exist in 1.09.1. 1.13/1.24/1.38 already curated.",
    )
    unresolved.setdefault(
        "cGcQuickMenu::cGcQuickMenu",
        "Sole caller cGcHUDManager::cGcHUDManager and callee ctors "
        "(cGcQuickActionMenu/cGcTerrainEditMenu/cGcNGui) are all unmapped; no "
        "string/imm64 anchor. (Not in 1.09.1.)",
    )
    unresolved.setdefault(
        "cGcVibrationManager::SendValue",
        "Small (TkID const&,float)->bool. Intersection of mapped callers' callees "
        "(Player/Weapon Update/Fire) yields no function taking a TkID+float; "
        "likely inlined at many call sites. imm64 is a shared FNV basis constant.",
    )
    unresolved.setdefault(
        "cTkAudioManager::Play_attenuated",
        "Wwise Play(TkAudioID,cTkVector3&,TkAudioObject,float). Only anchors are "
        "AK::SoundEngine::PostEvent/SetScalingFactor imports (unmapped) and many "
        "unmapped callers; no unique legacy signature isolated.",
    )
    unresolved.setdefault(
        "cTkInputPort::GetButton",
        "Overloaded/self-recursive input getter. Intersection of mapped callers' "
        "callees is empty under a small-size cap (inlined at most sites); no "
        "string/imm64 anchor.",
    )
    unresolved.setdefault(
        "cTkInputPort::SetButton",
        "All callers (cTkInputDeviceManager::Process*, cTkInputDualShock4::ReadImpl) "
        "are unmapped; no callees, strings, or imm64 to anchor on.",
    )
    unresolved.setdefault(
        "cTkStopwatch::GetDurationInSeconds",
        "~121-byte leaf calling cTkClock::GetSystemFrequency (unmapped). Called "
        "from many sites; the huge SimulationState::Render/ThreadedUpdate anchors "
        "give no unique small-callee. No distinctive constant.",
    )
    unresolved.setdefault(
        "cTkSystem::IntegratedGPUActive",
        "24-byte bool leaf reading a global. Callers (cTkEngineSettings::*, "
        "SimulationState::BuildRenderQueue) unmapped/huge; too generic to isolate "
        "without a second signal.",
    )

    for name in list(unresolved):
        if name in functions and len(functions[name]) == len(BUILDS):
            del unresolved[name]  # fully resolved after all

    json.dump({"functions": functions, "unresolved": unresolved}, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
