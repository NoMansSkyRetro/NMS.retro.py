"""Finder for the ``player_core`` batch (cGcPlayer:: / cGcPlayerState:: functions).

Prints one JSON object to stdout ({"functions": {...}, "unresolved": {...}}); all
reasoning goes to stderr. Deterministic and self-contained: every address is
re-derived from each build's decompilation DB plus the already-matched
``out/propagated_<build>.json`` anchors. No network, no manual steps.

Resolved (with the signal used):

* cGcPlayerState::AwardUnits  - the small function that references the "MONEY" stat
  string, calls _strupr + cGcStatsManager::Record, and *adds* its argument to the
  units field (its adjacent sibling *subtracts* = SpendUnits). Cross-checked in 1.38
  as a common callee of the mapped cGcFrontendPageShop::DoTrade and
  cGcPlayerDiscoveryHelper::DiscoveryUnitReward.
* cGcPlayerState::LoadFromData - the one large (>3 KB) function called by BOTH the
  mapped cGcGameState::LoadState and cGcGameState::LoadFromPersistentStorage, whose
  body copies data-struct fields (param_2) INTO the object (param_1) = load
  direction. Two of the three modern callers, in the gcplayerstate.cpp region.
* cGcPlayerState::SaveToData - LoadFromData's adjacent gcplayerstate.cpp sibling: the
  nearby large function whose body copies object fields (param_1) INTO the data struct
  (param_2) = save direction (it writes the units field param_1+0x114/0xf4 that
  AwardUnits owns). Save/Load are emitted adjacent by the compiler.

The remaining targets are left honestly unresolved (see ``UNRESOLVED`` below): their
modern strings are debug/node names that do not survive into the 2016-2017 builds,
their imm64 constants are generic, and the propagation left too few of their
callees/callers mapped to triangulate a unique start.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import BUILDS, Binary  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "out"
BUILDS_ORDER = ["1.09.1", "1.13", "1.24", "1.38"]

FUN = re.compile(r"FUN_(14[0-9a-f]+)")


def log(*a):
    print(*a, file=sys.stderr)


def prop_map(build):
    p = json.loads((OUT / f"propagated_{build}.json").read_text())
    return {k: int(v["address"], 16) for k, v in p.items()}


def decomp(b, addr):
    row = b.function_at(addr)
    return row[3] if row else None


def callees(b, addr):
    d = decomp(b, addr)
    if not d:
        return set()
    return {int(m.group(1), 16) for m in FUN.finditer(d) if int(m.group(1), 16) != addr}


def size_of(b, addr):
    row = b.function_at(addr)
    return row[2] if row else None


def rows_by_addr(b):
    return b.db.execute(
        "SELECT address, size FROM decompilations ORDER BY address"
    ).fetchall()


def direction_scores(b, addr):
    """(load_score, save_score): field copies data->this vs this->data."""
    d = decomp(b, addr) or ""
    load = len(re.findall(r"\(param_1 \+ 0x[0-9a-f]+\) = \*\(\w+ \*\)\(param_2", d))
    load += len(re.findall(r"param_1\[[^\]]+\] = (?:\*\(\w+ \*\)\(param_2|param_2\[)", d))
    save = len(re.findall(r"\(param_2 \+ 0x[0-9a-f]+\) = \*\(\w+ \*\)\(param_1", d))
    save += len(re.findall(r"param_2\[[^\]]+\] = (?:\*\(\w+ \*\)\(param_1|param_1\[)", d))
    return load, save


# ---------------------------------------------------------------------------
# cGcPlayerState::AwardUnits
# ---------------------------------------------------------------------------
def find_award_units(b):
    rows = b.db.execute(
        "SELECT address, size, raw_decomp FROM decompilations "
        "WHERE size < 400 AND raw_decomp LIKE '%_strupr%' AND raw_decomp LIKE '%MONEY%'"
    ).fetchall()
    hits = []
    for a, s, d in rows:
        fields = set(re.findall(r"\(param_1 \+ (0x[0-9a-f]+)\) = ", d))
        for fld in fields:
            is_sub = re.search(
                rf"- \*\(\w+ \*\)\(param_1 \+ {fld}\)|\(param_1 \+ {fld}\) - |uVar\d - uVar\d",
                d,
            )
            is_add = (
                f"+ *(uint *)(param_1 + {fld})" in d
                or f"+ *(int *)(param_1 + {fld})" in d
                or re.search(rf"\(param_1 \+ {fld}\) \+ param_2", d)
            )
            if is_add and not is_sub:
                hits.append((a, s, fld))
                break
    if len(hits) == 1:
        return hits[0][0]
    log(f"    AwardUnits: expected 1 add-MONEY candidate, got {[hex(h[0]) for h in hits]}")
    return None


# ---------------------------------------------------------------------------
# cGcPlayerState::LoadFromData / SaveToData
# ---------------------------------------------------------------------------
def find_load_save(b, pm):
    ls = pm.get("cGcGameState::LoadState")
    lp = pm.get("cGcGameState::LoadFromPersistentStorage")
    if not (ls and lp):
        log(f"    Load/Save: missing anchors LoadState={ls} LoadFromPersistentStorage={lp}")
        return None, None
    shared = callees(b, ls) & callees(b, lp)
    load = None
    for x in sorted(shared, key=lambda z: -(size_of(b, z) or 0)):
        if (size_of(b, x) or 0) <= 3000:
            continue
        ld, sv = direction_scores(b, x)
        if ld > sv:
            load = x
            break
    if load is None:
        log("    Load/Save: no large load-direction shared callee found")
        return None, None
    # SaveToData: the adjacent large save-direction sibling in the same unit.
    rows = rows_by_addr(b)
    idx = next((i for i, (a, _) in enumerate(rows) if a == load), None)
    save = None
    if idx is not None:
        best = None
        for j in range(max(0, idx - 3), min(len(rows), idx + 6)):
            a2, s2 = rows[j]
            if a2 == load or s2 <= 2500:
                continue
            ld, sv = direction_scores(b, a2)
            if sv > ld and sv > 20:
                # prefer the closest such sibling by address distance
                dist = abs(a2 - load)
                if best is None or dist < best[0]:
                    best = (dist, a2)
        if best:
            save = best[1]
    if save is None:
        log(f"    SaveToData: no adjacent save-direction sibling of 0x{load:X}")
    return load, save


UNRESOLVED = {
    "cGcPlayer::CheckFallenThroughFloor": "only caller is cGcPlayer::Update (>20 same-caller callees); modern strings (VOLCANO) and callees (raycast/gravity) are not distinctively mapped in legacy - no unique start",
    "cGcPlayer::GetDominantHand": "VR accessor calling cTkHmdOpenVR::GetInstance; OpenVR/VR support post-dates all four builds (Beyond 2.0, 2019) - function absent, no legacy signature",
    "cGcPlayer::OnEnteredCockpit": "modern 'IN_SHIP' string only survives as a substring of unrelated tokens; callers cGcVehicleCockpit::DoEnter / cGcPlayerDissapearEffect::End not mapped - no unique signal",
    "cGcPlayer::RenderInventoryEditor": "debug NGui editor; modern menu strings (Give All, Add Suit Slot, ...) absent in 2016-2017 builds; only caller RenderNGui maps but its legacy body is a much smaller dialog handler - no reliable start",
    "cGcPlayer::RenderNGui": "already curated for 1.24/1.38; for 1.09.1/1.13 the modern debug-menu strings are absent and Steam-Workshop-era code paths post-date these builds - could not port",
    "cGcPlayer::SetToPosition": "small (186B); calls SetFacing/UpdateGraphics (unmapped) and Havok SetPosition; 12 callers of which only Update/SwitchToAnimatedCamera map, yielding only generic high-in-degree helpers - no unique start",
    "cGcPlayer::TakeDamage": "large; only mapped caller is cGcPlayer::Update; damage-audio strings and health callees not distinctively mapped - several same-caller candidates, none uniquely confirmable",
    "cGcPlayer::UpdateGraphics": "callers (Update/CheckFallenThroughFloor/SetToPosition/...) mostly unmapped; imm64 0x290F44A850290F44 is a generic packed constant (194 funcs); no distinctive string - no unique start",
    "cGcPlayerState::AwardNanites": "no 'NANITES' stat string in any legacy build and no add-and-return signature on a nanites field; only Record as modern callee - not distinguishable from other small accessors",
    "cGcPlayerState::GetStatValue": "float stat accessor; calls the mapped GetInventoryStoreFromChoice but so do ~69 functions; its item-lookup helpers (GetPrimaryItemForStat-style) return pointers and shadow it - no unique start",
    "cGcPlayerState::StoreCurrentSystemSpaceStationEndpoint": "104B; only modern callee Engine::IterateNode is unmapped; 'SpawnPos' survives only inside longer node tokens; common callees of mapped Update/Interact are generic helpers - no unique start",
    "cGcPlayerState::cGcPlayerState": "constructor; caller cGcGameState::cGcGameState and member-ctor anchors (cGcInventoryStore::cGcInventoryStore) unmapped; imm64 0xC4CEB9FE1A85EC53 absent from legacy .text - no anchor",
}


def main():
    functions = {}
    unresolved = dict(UNRESOLVED)

    for build in BUILDS_ORDER:
        if build not in BUILDS:
            continue
        log(f"[{build}]")
        b = Binary(build)
        pm = prop_map(build)

        au = find_award_units(b)
        if au:
            functions.setdefault("cGcPlayerState::AwardUnits", {})[build] = f"0x{au:X}"
            log(f"    AwardUnits = 0x{au:X}")

        load, save = find_load_save(b, pm)
        if load:
            functions.setdefault("cGcPlayerState::LoadFromData", {})[build] = f"0x{load:X}"
            log(f"    LoadFromData = 0x{load:X}")
        if save:
            functions.setdefault("cGcPlayerState::SaveToData", {})[build] = f"0x{save:X}"
            log(f"    SaveToData = 0x{save:X}")

    # Drop any target that ended up resolved from the unresolved map.
    for name in list(unresolved):
        if name in functions:
            del unresolved[name]

    print(json.dumps({"functions": functions, "unresolved": unresolved}))


if __name__ == "__main__":
    main()
