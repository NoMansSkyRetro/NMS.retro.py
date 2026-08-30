"""Finder for the ``player_aux`` batch.

Targets: cGcPlayerWeapon / cGcPlayerWanted / cGcPlayerCommunicator /
cGcPlayerCharacterComponent / cGcPlayerDiscoveryHelper / cGcPlayerEnvironment /
cGcPlayerHUD functions.

Prints ONE JSON object to stdout ({"functions": {...}, "unresolved": {...}}); all
reasoning goes to stderr. Deterministic and self-contained: every address is
re-derived from each build's binary + decompilation DB plus the already-matched
``out/propagated_<build>.json`` anchors. No network, no manual steps.

Signals used (all cross-checked against ``Binary.function_at`` for a real start):

* cGcPlayerEnvironment::Update  - HIGH PRIORITY (miNearestPlanetIndex owner that
  NMS-Newton depends on). Located by its profiler NAME LITERAL: in the 2016-2018
  builds this logic is a single monolithic function
  ``cGcEnvironment::UpdatePlayerEnvironmentState(float)`` (4.13 later refactored it
  into the component method cGcPlayerEnvironment::Update). Exactly one function in
  each build embeds that literal - a lock (HUNTING.md method #5). All four builds.

* cGcPlayerHUD::RenderCrosshair - the unique function referencing ALL of the
  crosshair-state strings OVERHEAT + TARGET + RELOAD + NORMAL + AMOUNT (HITMARKER in
  1.13+, packed imm "HITMARKE" in 1.09.1). One owner per build. All four builds.

* cGcPlayerHUD::RenderWeaponPanel - the unique owner of the weapon-name-label string
  WEAPON_LABEL that is also a direct callee of the mapped
  cGcPlayerHUD::RenderOffscreen2D. Two signals. All four builds (in 1.09.1 the panel
  additionally carries the jetpack indicator, which was split out into
  RenderIndicatorPanel by 1.13).

* cGcPlayerHUD::RenderIndicatorPanel - the RenderOffscreen2D child owning the player
  status-indicator strings JETPACK + STAMINA (jetpack/stamina/scanner/inventory
  indicators). 1.13 / 1.24 / 1.38. Absent as a distinct function in 1.09.1 (the
  indicators had not been split out of the weapon panel; STAMINA/SCANNER strings do
  not exist yet).

* cGcPlayerHUD::Update - the unique owner of INTRCT_CLAIM_BASE, a HUD::Update-specific
  interaction-prompt string (a single-owner string = lock). 1.13 / 1.24 / 1.38.
  Absent in 1.09.1 (base claiming is a post-Foundation feature; the string and the
  rest of HUD::Update's distinctive strings do not exist at launch).

Everything else is left honestly unresolved (see UNRESOLVED): tiny ICF-folded /
inlined accessors (IsOnPlanet 16B, IsOnboardOwnFreighter 69B, the weapon charge
pair), a generic-imm death-state setter, and no-string component/update functions
whose modern anchors (GetStatValue, GetCreatureInfoFromDiscoveryData, the interaction
helpers, cGcWitness::Update, ...) are themselves unmapped in these builds.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common import BUILDS, Binary  # noqa: E402
import propagate_symbols as ps  # noqa: E402  (its Side/init logs to stderr only)

OUT = ROOT / "out"
BUILDS_ORDER = ["1.09.1", "1.13", "1.24", "1.38"]


def log(*a):
    print(*a, file=sys.stderr)


def prop_map(build):
    p = json.loads((OUT / f"propagated_{build}.json").read_text())
    return {k: int(v["address"], 16) for k, v in p.items()}


def str_owner_index(side):
    """string(bytes) -> set(func_va). Side.prints stores strings as bytes tokens."""
    idx = {}
    for va, toks in side.prints.items():
        for t in toks:
            if isinstance(t, (bytes, bytearray)):
                idx.setdefault(bytes(t), set()).add(va)
    return idx


def owners_all(idx, *strs):
    """Functions referencing every one of `strs`."""
    res = None
    for s in strs:
        o = idx.get(s.encode(), set())
        res = set(o) if res is None else (res & o)
    return res or set()


def unique_start(b, cands, label):
    """Exactly one candidate that is a verified function start, else None."""
    starts = [c for c in cands if b.function_at(c)]
    if len(starts) == 1:
        return starts[0]
    log(f"    {label}: expected 1 start, got {[hex(c) for c in sorted(starts)]}")
    return None


UNRESOLVED = {
    "cGcPlayerHUD::RenderIndicatorPanel@1.09.1": (
        "no separate indicator panel at launch: JETPACK is folded into the weapon "
        "panel (0x14048EA50) and the STAMINA/SCANNER indicator strings do not exist"
    ),
    "cGcPlayerHUD::Update@1.09.1": (
        "INTRCT_CLAIM_BASE and the other distinctive HUD::Update strings (scriptName, "
        "UI_STATION_ENTRY, CAPITAL_SHIP_NAME_L, ...) are post-Foundation; %NAME%/%RACE% "
        "have multiple owners - no unique start in the launch HUD"
    ),
    "cGcPlayerEnvironment::IsOnPlanet": (
        "16-byte accessor reading the nearest-planet field; ICF-folded/inlined and its "
        "only mapped caller (RenderWeaponPanel) shares just generic STL helpers - no "
        "unique start"
    ),
    "cGcPlayerEnvironment::IsOnboardOwnFreighter": (
        "69-byte freighter-state accessor; inlined/ICF-folded - intersecting the callees "
        "of its mapped callers (TriggerAction, InteractionComponent::Interact, "
        "FrontendPageInteractions::DoInteraction) yields only __security_check_cookie"
    ),
    "cGcPlayerCharacterComponent::Update": (
        "modern strings JEMMC_%d_%d / CamoEffectMaterial_%d are post-launch (camo/JEMMC "
        "features); MusicVolume has 3 generic owners; the no-string children of the "
        "mapped cGcPlayer::Update cannot be told apart - no unique start"
    ),
    "cGcPlayerCharacterComponent::SetDeathState": (
        "only hint is imm64 0x9DDFEA08EB382D69, which is a generic constant present in "
        "50+ functions per build; caller SetCharacterState is unmapped - no anchor"
    ),
    "cGcPlayerCommunicator::Update": (
        "no strings; not a resolvable direct callee of the mapped cGcPlayer::Update in "
        "legacy, and its interaction/engine callees (FindFirstTypedComponent, "
        "GetInteraction, RequestRemoveNode, ...) are unmapped - no unique start"
    ),
    "cGcPlayerWanted::Update": (
        "debug strings LAST KNOWN PLAYER POS / LAST KNOWN DRONE CRIME POS are absent; "
        "cGcDroneComponentData is non-distinctive (~20 owners); the closest witness/drone "
        "candidate (1.38 0x140EC3280) is NOT called by cGcPlayer::Update, so it is likely "
        "cGcWitness::Update or a sub-helper, not Wanted::Update - unconfirmed"
    ),
    "cGcPlayerDiscoveryHelper::GetDiscoveryWorth": (
        "416-byte helper whose distinctive callees (cGcPlanetGenerator::"
        "GetCreatureInfoFromDiscoveryData, cGcPlayerState::GetStatValue) are unmapped; "
        "too many mid-size callees of the mapped cGcBinoculars::PopulateDiscoveryInfo to "
        "isolate a unique start"
    ),
    "cGcPlayerWeapon::GetChargeTime": (
        "147-byte stat accessor calling the unresolved cGcPlayerState::GetStatValue; "
        "callers (GetChargeFactor, cGcPlayerWeapon::Update) unmapped - no unique anchor"
    ),
    "cGcPlayerWeapon::GetChargeFactor": (
        "65-byte wrapper whose only callee is the (also unresolved) GetChargeTime; many "
        "such tiny wrapper pairs exist - no way to isolate a unique start"
    ),
    "cGcPlayerHUD::cGcPlayerHUD": (
        "constructor; its callees (cGcHUD::cGcHUD, cGcHUDMarker/TrackArrow ctors, "
        "cGcNGui::cGcNGui, cGcNGuiLayer::cGcNGuiLayer) and its sole caller "
        "cGcHUDManager::cGcHUDManager are all unmapped - no anchor"
    ),
}


def main():
    functions = {}

    for build in BUILDS_ORDER:
        if build not in BUILDS:
            continue
        log(f"[{build}]")
        b = Binary(build)
        side = ps.load_side_build(build)
        idx = str_owner_index(side)
        pm = prop_map(build)

        def emit(name, va):
            if va:
                functions.setdefault(name, {})[build] = f"0x{va:X}"
                log(f"    {name} = 0x{va:X}")

        # --- cGcPlayerEnvironment::Update (name literal, HIGH PRIORITY) ---
        rows = b.functions_matching("%UpdatePlayerEnvironmentState%")
        env = unique_start(b, [r[1] for r in rows], "Environment::Update")
        emit("cGcPlayerEnvironment::Update", env)

        # --- RenderCrosshair: unique owner of the crosshair-state string set ---
        cross = unique_start(
            b,
            owners_all(idx, "OVERHEAT", "TARGET", "RELOAD", "NORMAL", "AMOUNT"),
            "RenderCrosshair",
        )
        emit("cGcPlayerHUD::RenderCrosshair", cross)

        # --- RenderOffscreen2D anchor for the two panels ---
        ro = pm.get("cGcPlayerHUD::RenderOffscreen2D")
        ro_kids = side.callees.get(ro, set()) if ro else set()
        if not ro:
            log("    RenderOffscreen2D anchor missing; skipping weapon/indicator panels")

        # --- RenderWeaponPanel: WEAPON_LABEL owner that RenderOffscreen2D calls ---
        wp = unique_start(
            b, owners_all(idx, "WEAPON_LABEL") & ro_kids, "RenderWeaponPanel"
        )
        emit("cGcPlayerHUD::RenderWeaponPanel", wp)

        # --- RenderIndicatorPanel: JETPACK+STAMINA indicator child (1.13+) ---
        ip = unique_start(
            b, owners_all(idx, "JETPACK", "STAMINA") & ro_kids, "RenderIndicatorPanel"
        )
        emit("cGcPlayerHUD::RenderIndicatorPanel", ip)

        # --- HUD::Update: unique owner of INTRCT_CLAIM_BASE (1.13+) ---
        hu = unique_start(b, owners_all(idx, "INTRCT_CLAIM_BASE"), "HUD::Update")
        emit("cGcPlayerHUD::Update", hu)

    print(json.dumps({"functions": functions, "unresolved": UNRESOLVED}))


if __name__ == "__main__":
    main()
