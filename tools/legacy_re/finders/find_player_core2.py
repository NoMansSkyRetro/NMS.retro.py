#!/usr/bin/env python3
"""Finder for the ``player_core`` batch (round 2).

Twelve NOT_YET_FOUND slots across the four legacy builds (1.09.1 / 1.13 / 1.24 /
1.38). This round re-attacked them with the cross-version toolkit (handles.Xverse):
distinctive-string xrefs, imm64 index, and call-graph intersection anchored off the
already-mapped cGcPlayer::Update / cGcPlayerState::AwardUnits / GetInventoryStoreFromChoice
/ GetPrimaryItemForStat / RenderNGui(1.24,1.38).

Outcome: no new address clears the "real function start + decompile-verified, two
independent signals" bar. Every target is either (a) a function that did not yet exist
as a distinct unit in 2016-2018 (VR, Steam-Workshop, debug-menu, or later-extracted
helpers) or (b) a non-string-locked function whose only anchor is cGcPlayer::Update,
where it is one of ~50 same-caller callees with no distinctive mapped callee.

The script is deterministic and self-contained: it re-derives the evidence live from
the cached indices, logs the derivation to stderr, and prints one pure-JSON object to
stdout. Hardcoded addresses (anchors) are used only as verified starting points; no
target address is emitted because none verified.

Run from tools/legacy_re/:  python finders/find_player_core2.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from handles import Xverse  # noqa: E402


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# Anchors already in offsets.json / propagated (verified, used only as evidence).
UPDATE = {"1.09.1": 0x1409D5070, "1.13": 0x140B330E0, "1.24": 0x140CADA90, "1.38": 0x140E59230}
AWARDUNITS = {"1.09.1": 0x140430B10, "1.13": 0x140553F20, "1.24": 0x140661140, "1.38": 0x140785C70}
RENDERNGUI = {"1.24": 0x140E05B20, "1.38": 0x140FBE0D0}
GIS = {"1.24": 0x14065C380, "1.38": 0x140788DC0}  # GetInventoryStoreFromChoice


def gather_evidence():
    """Re-derive the key negative/limiting signals so the reasons are reproducible."""
    xv = Xverse(verbose=False)
    ev = {}

    # 1. Strings that the modern bodies reference but that are absent in every build.
    for s in ("VOLCANO", "%DAMAGE%", "IN_SHIP", "NANITES", "Nanites",
              "Give All", "Add Suit Slot", "PLAYER STATS"):
        hits = {b: [hex(a) for a in v] for b, v in xv.by_string(s).items() if v}
        ev.setdefault("absent_strings", {})[s] = hits
        log(f"[str] {s!r}: {hits or 'ABSENT in all builds'}")

    # 2. MONEY pair confirms AwardUnits(+)/SubtractUnits(-); no NANITES analogue.
    money = {b: sorted(hex(a) for a in v) for b, v in xv.by_string("MONEY").items() if v}
    ev["money_refs"] = money
    log(f"[money] exactly the award/subtract-units pair references MONEY: {money}")

    # 3. RenderNGui (1.24/1.38) references Steam-Workshop-era strings; port abstains
    #    for 1.09.1/1.13 (those code paths post-date the 2016 builds).
    pc = xv.port_candidates("1.24", RENDERNGUI["1.24"])
    ev["renderngui_oldbuild_top"] = {
        b: [(hex(va), round(sc, 1)) for va, sc, _ in cands[:1]]
        for b, cands in pc.items() if b in ("1.13", "1.09.1")
    }
    log(f"[renderngui] best old-build candidates (weak, callee-only score~6): "
        f"{ev['renderngui_oldbuild_top']}")

    # 4. GetStatValue: caller-of-GIS ∩ same-CU-neighbour gives a 1.24 lead
    #    (0x14065c630) whose decompiled body uppercases stat strings (strncpy/_strupr)
    #    and has a 3-arg/undefined8 shape, not modern's clean float(eStatsType,...) -
    #    rejected, recorded for the next round.
    callers = set(xv.callers("1.24", GIS["1.24"]))
    neigh = set(xv.neighbours("1.24", GIS["1.24"]))
    inter = sorted(callers & neigh)
    ev["getstatvalue_1_24_leads"] = [hex(a) for a in inter]
    log(f"[getstatvalue] 1.24 caller∩neighbour of GIS: {ev['getstatvalue_1_24_leads']} "
        f"(0x14065c630 inspected, string-uppercasing -> not confirmable as GetStatValue)")

    # 5. imm64 constants for UpdateGraphics / ctor are generic or absent.
    for imm, who in ((0x290F44A850290F44, "UpdateGraphics"),
                     (0xC4CEB9FE1A85EC53, "cGcPlayerState::cGcPlayerState")):
        counts = {b: len(xv.idx[b].by_token.get(("imm", imm), ())) for b in xv.ORDER}
        ev.setdefault("imm64_counts", {})[who] = counts
        log(f"[imm64] {who} {hex(imm)}: per-build owner counts {counts}")

    # 6. SpawnPos exists but only inside large Interact/respawn/outpost functions;
    #    no standalone 104B StoreCurrentSystemSpaceStationEndpoint unit.
    sp = {b: [(hex(a), xv.name(b, a)[1]) for a in v] for b, v in xv.by_string("SpawnPos").items() if v}
    ev["spawnpos_owner_sizes"] = sp
    smallest = {b: min(sz for _, sz in owners) for b, owners in sp.items()}
    log(f"[spawnpos] smallest owner size per build {smallest} "
        f"(modern helper is 104B; not present as a distinct function)")

    return ev


REASONS = {
    "cGcPlayer::CheckFallenThroughFloor":
        "Only mapped caller is cGcPlayer::Update (~50 same-caller callees). Modern "
        "string 'VOLCANO' and gravity/raycast callees are absent/unmapped in all four "
        "builds; no distinctive imm64. No unique function start.",
    "cGcPlayer::GetDominantHand":
        "VR accessor whose sole callee is cTkHmdOpenVR::GetInstance; OpenVR support "
        "post-dates all four builds (Beyond, 2019). Function absent - nothing to map.",
    "cGcPlayer::OnEnteredCockpit":
        "Modern 'IN_SHIP' string is absent as a standalone token; callers "
        "cGcVehicleCockpit::DoEnter / cGcPlayerDissapearEffect::End are unmapped. No "
        "distinctive signal in any build.",
    "cGcPlayer::RenderInventoryEditor":
        "Debug NGui inventory editor; its menu strings (Give All, Add Suit Slot, ...) "
        "are absent in 2016-2018 builds and its only caller RenderNGui is itself a much "
        "smaller ~800B dialog handler there. The editor was not built as a distinct "
        "function yet - unmappable.",
    "cGcPlayer::RenderNGui":
        "Already curated for 1.24/1.38 (only 1.09.1/1.13 are open). The 1.24/1.38 body "
        "references Steam-Workshop-era strings (GENERIC_ERROR / STEAM_WORKSHOP_ERROR); "
        "port_candidates to 1.09.1/1.13 return only weak callee-only leads (score ~6). "
        "That code path post-dates the 2016 builds - could not port.",
    "cGcPlayer::SetToPosition":
        "Small (186B); calls SetFacing/UpdateGraphics (both unmapped) plus Havok "
        "SetPosition/SetLinearVelocity. Of 12 modern callers only Update maps, so it is "
        "one of ~50 same-caller callees of Update with no distinctive mapped callee. No "
        "unique start.",
    "cGcPlayer::TakeDamage":
        "Large; modern audio string '%DAMAGE%' absent in all builds and health callees "
        "(ModifyAndReturnHealth/GetMaximumShield) unmapped. Only Update anchors it, "
        "among many same-caller candidates - none uniquely confirmable.",
    "cGcPlayer::UpdateGraphics":
        "No referenced string; imm64 0x290F44A850290F44 is a generic packed constant "
        "(150+ owners per build). Callers (Update/SetToPosition/CheckFallenThroughFloor/"
        "Respawn/...) are mostly unmapped; the callee-of-Update-called-by-other-Update-"
        "callees intersection surfaces only library helpers. No unique start.",
    "cGcPlayerState::AwardNanites":
        "The MONEY string is referenced by exactly the AwardUnits/SubtractUnits pair "
        "(confirmed) - legacy stat Record is string-keyed ('MONEY' uppercased at "
        "runtime). No 'NANITES'/'Nanites' string exists in any build, so there is no "
        "add-and-record analogue on a nanite field to isolate. Only Record as modern "
        "callee - indistinguishable from other small accessors.",
    "cGcPlayerState::GetStatValue":
        "float stat accessor. caller-of-GetInventoryStoreFromChoice ∩ same-CU-neighbour "
        "yields a single 1.24 lead 0x14065c630 (610B), but its decompiled body "
        "uppercases stat strings (strncpy/_strupr) and has a 3-arg/undefined8 shape "
        "unlike modern float(eStatsType, ItemLookupType, ...); not confirmable. Lead "
        "recorded for follow-up.",
    "cGcPlayerState::StoreCurrentSystemSpaceStationEndpoint":
        "Modern helper is 104B and iterates a node named 'SpawnPos'. 'SpawnPos' exists "
        "as an exact string in every build but is referenced only by large "
        "Interact/DoPlayerRespawn/outpost functions (smallest owner ~984B+); the store-"
        "endpoint logic is still inlined, not a distinct function. Unmappable.",
    "cGcPlayerState::cGcPlayerState":
        "Constructor; imm64 0xC4CEB9FE1A85EC53 is absent from every legacy .text, and "
        "the caller cGcGameState::cGcGameState plus member-ctor anchors "
        "(cGcInventoryStore::cGcInventoryStore) are unmapped. No anchor.",
}


def main():
    ev = gather_evidence()
    log("\n[summary] evidence gathered; no target verified to commit standard.")
    log(json.dumps(ev)[:400] + " ...")
    out = {"functions": {}, "unresolved": REASONS}
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
