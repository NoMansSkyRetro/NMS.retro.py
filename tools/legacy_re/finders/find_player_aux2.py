"""Round-2 finder for the ``player_aux`` batch.

Round 1 (``find_player_aux.py``) located the cGcPlayerHUD render cluster and
cGcPlayerEnvironment::Update from *modern* hint strings, and honestly left the rest
unresolved. Round 2 re-hunts the still-NOT_YET_FOUND slots with the cross-version
toolkit (``handles.Xverse``) plus a signal round 1 could not see: **legacy-only
strings**. The modern (4.13) hint set for cGcPlayerCommunicator::Update is empty, but
every legacy build still carries that class's animation-state strings, so the round-1
string-from-hints method missed it.

Resolved this round
-------------------
* cGcPlayerCommunicator::Update  - all four builds. The communicator is the little
  floating message drone; its per-frame Update drives the fly-in/hover animation and
  raises the interaction. In 1.13/1.24/1.38 it is the UNIQUE owner of the animation
  state string ``ATTRACT_OUT`` (1.24/1.38 also own AWAKEIDLE + HOVER) AND a direct
  caller of the mapped cGcInteractionComponent::DoInteractionEvent - two independent
  signals. In 1.09.1 the string table has no ATTRACT_* literal, but the function builds
  the name inline as the packed immediate 0x5f54434152545441 ("ATTRACT_", little-endian)
  then _strupr()s it; it is the one DoInteractionEvent caller carrying that immediate.
  Sizes match the modern 2508-byte Update (1.38 2536B, 1.24 2522B; 1.13 1668B / 1.09.1
  1574B are the earlier, pre-AWAKEIDLE/HOVER form). Decompile-verified: player-distance
  test + Engine node-activation + DoInteractionEvent, i.e. Update(float) semantics.

Everything else stays unresolved (see UNRESOLVED). Round 2 re-checked each with the
call graph and cross-version indices and the round-1 verdict holds: the accessors are
ICF-folded/inlined (IsOnPlanet's only surviving RenderWeaponPanel callees are 170-330
caller generic STL helpers), the camo/JEMMC strings behind CharacterComponent::Update do
not exist pre-4.x, GetDiscoveryWorth has no isolator among ~50 PopulateDiscoveryInfo
callees, and the Wanted/Witness cluster (1.38 0x140ec3280 = the multi-component-data
scanner, 4365B) is not reachable from the mapped cGcPlayer::Update.

Deterministic and self-contained: DoInteractionEvent anchors are read from
offsets.json; every address is re-derived from each build's string/call-graph index and
checked for a real function start. stdout is pure JSON, all reasoning goes to stderr.
"""

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common import Binary  # noqa: E402
from handles import Xverse  # noqa: E402

BUILDS_ORDER = ["1.09.1", "1.13", "1.24", "1.38"]
OFFSETS = ROOT.parent.parent / "nmspy" / "data" / "offsets.json"
ATTRACT_IMM = 0x5F54434152545441  # "ATTRACT_" packed little-endian


def log(*a):
    print(*a, file=sys.stderr)


def doie_anchor(build):
    o = json.loads(OFFSETS.read_text())["functions"]
    v = o["cGcInteractionComponent::DoInteractionEvent"].get(build, "NOT_YET_FOUND")
    return int(v, 16) if v.startswith("0x") else None


def one(cands, b, label):
    starts = sorted(c for c in cands if b.function_at(c))
    if len(starts) == 1:
        return starts[0]
    log(f"    {label}: expected 1 start, got {[hex(c) for c in starts]}")
    return None


def find_communicator(build, xv, b):
    """cGcPlayerCommunicator::Update: DoInteractionEvent caller that owns the
    ATTRACT_ animation name (string literal, or packed immediate in 1.09.1)."""
    doie = doie_anchor(build)
    if not doie:
        log(f"    Communicator::Update: no DoInteractionEvent anchor in {build}")
        return None
    callers = set(xv.callers(build, doie))

    owners = set(xv.by_string("ATTRACT_OUT").get(build, []))
    if owners:
        return one(owners & callers, b, "Communicator::Update(str)")

    # 1.09.1: no ATTRACT_* literal in the string table; the name is built inline as
    # the packed immediate then strupr'd. Pick the DoInteractionEvent caller whose
    # decompilation carries that immediate.
    cur = b.db.cursor()
    hits = set()
    for a in callers:
        cur.execute("SELECT raw_decomp FROM decompilations WHERE address=?", (a,))
        row = cur.fetchone()
        if row and row[0] and (f"0x{ATTRACT_IMM:x}" in row[0]):
            hits.add(a)
    return one(hits, b, "Communicator::Update(imm)")


UNRESOLVED = {
    "cGcPlayerCharacterComponent::SetDeathState": (
        "no strings; only hint is the generic FNV-basis imm64 0x9DDFEA08EB382D69 "
        "(50+ owners/build). Caller SetCharacterState and callees "
        "(cGcAnimationLayerQueue::Play, AddStatusMessage_Internal) are unmapped - no "
        "anchor. Same gcplayercharactercomponent.cpp unit has no mapped sibling."
    ),
    "cGcPlayerCharacterComponent::Update": (
        "7261B callee of the mapped cGcPlayer::Update, but its modern markers are "
        "post-launch: CamoEffectMaterial_%d / JEMMC_%d_%d strings are absent in all "
        "four builds and MusicVolume resolves only to the settings-serialiser. The "
        "one big stringless Player::Update callee (1.38 0x140e60d60, 7087B) is "
        "vector-math and does not touch the ThirdPerson-anim owner - unconfirmable."
    ),
    "cGcPlayerDiscoveryHelper::GetDiscoveryWorth": (
        "416B, no strings; distinctive callees (GetCreatureInfoFromDiscoveryData, "
        "cGcPlayerState::GetStatValue) unmapped. The mapped caller "
        "cGcBinoculars::PopulateDiscoveryInfo has ~50 callees with no ~416B/3-callee "
        "isolator - cannot pick a unique start."
    ),
    "cGcPlayerEnvironment::IsOnPlanet": (
        "16B nearest-planet accessor; ICF-folded/inlined. Its only mapped caller "
        "RenderWeaponPanel keeps no <60B callee below 170 callers (all generic STL "
        "helpers), i.e. IsOnPlanet is not emitted as a standalone function."
    ),
    "cGcPlayerEnvironment::IsOnboardOwnFreighter": (
        "69B freighter-state accessor; inlined/ICF-folded - intersecting the callees "
        "of its mapped callers yields only __security_check_cookie."
    ),
    "cGcPlayerWanted::Update": (
        "4983B; debug strings LAST KNOWN PLAYER POS / LAST KNOWN DRONE CRIME POS are "
        "stripped and cGcDroneComponentData has ~14-20 owners/build. The wanted/witness "
        "cluster (1.38 0x140ec3280, 4365B multi-component-data scanner = likely "
        "cGcWitness::Update) is NOT reachable from the mapped cGcPlayer::Update, so no "
        "graph anchor isolates Wanted::Update."
    ),
    "cGcPlayerWeapon::GetChargeTime": (
        "147B stat accessor calling the unmapped cGcPlayerState::GetStatValue; callers "
        "(GetChargeFactor, cGcPlayerWeapon::Update) unmapped - no unique anchor."
    ),
    "cGcPlayerWeapon::GetChargeFactor": (
        "65B wrapper whose only callee is the (also unresolved) GetChargeTime; many "
        "such tiny wrapper pairs exist - no way to isolate a unique start."
    ),
    "cGcPlayerHUD::cGcPlayerHUD": (
        "constructor; its member ctors (cGcHUD, cGcHUDMarker/TrackArrow, cGcNGui, "
        "cGcNGuiLayer) and sole caller cGcHUDManager::cGcHUDManager are unmapped, and "
        "cGcPlayerHUD is not virtual-dispatched (no vtable ptr to HUD::Update in "
        ".rdata), so no anchor. The mapped LoadData's single caller (1.38 0x1408d09b0, "
        "texture-loading Init) is not the member-ctor constructor."
    ),
    "cGcPlayerHUD::RenderIndicatorPanel@1.09.1": (
        "no separate indicator panel at launch: JETPACK is folded into the weapon "
        "panel and the STAMINA/SCANNER indicator strings do not exist yet."
    ),
    "cGcPlayerHUD::Update@1.09.1": (
        "INTRCT_CLAIM_BASE and the other distinctive HUD::Update strings are "
        "post-Foundation; no unique start in the launch HUD."
    ),
}


def main():
    xv = Xverse()
    functions = {}

    for build in BUILDS_ORDER:
        log(f"[{build}]")
        b = Binary(build)

        va = find_communicator(build, xv, b)
        if va:
            functions.setdefault("cGcPlayerCommunicator::Update", {})[build] = f"0x{va:X}"
            log(f"    cGcPlayerCommunicator::Update = 0x{va:X} ({b.function_at(va) and 'start ok'})")

    print(json.dumps({"functions": functions, "unresolved": UNRESOLVED}))


if __name__ == "__main__":
    main()
