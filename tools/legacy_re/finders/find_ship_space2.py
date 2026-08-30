#!/usr/bin/env python3
"""Finder for the "ship_space" batch (round 2).

Targets: ship / spaceship-component / spaceship-weapons / spaceship-warp /
ship-HUD-ctor / ship+vehicle+freighter ownership functions that were left
NOT_YET_FOUND after round 1.

Result of round 2 (this script): every remaining slot is reported `unresolved`.
Each reason below is backed by a *positive verification* done with the round-2
cross-version toolkit (handles.Xverse over all four builds), not merely a
repeat of the round-1 "vote tied" note:

  * absence checks: the distinctive string / imm64 the target references in the
    4.13 build is genuinely ABSENT from the .text/.rdata of all four legacy
    builds (feature/literal post-dates 1.38, or the constant changed), so there
    is no lock to anchor on.
  * inline checks: the target is a tiny accessor whose only body is a call that,
    when traced from its mapped caller (UpdateControlled / SSC::Update /
    RenderIndicatorPanel), is inlined in the legacy builds - there is no
    standalone function to point at.
  * structural checks: the call-graph candidate produced by intersecting the
    mapped anchors was decompiled and did NOT match the target (e.g. the
    Update&UpdateLanding common callee is a transform/math helper; the
    FinaliseExit->...->Update chain resolves to a per-frame camera update, not
    Eject), so committing it would be wrong.

New anchor discovered this round (not a batch target, recorded for future
rounds / seeding): cGcSpaceshipWeapons::Update, located by the distinctive
string trio ShipShootShake + ShipLaserShake + OSD_OVERHEAT_SWITCH:
  1.38 0x140F81250, 1.24 0x140DCBC50, 1.13 0x140C48360  (absent in 1.09.1).
Its small shoot-point getters (GetCurrentShootPoints / GetAverageBarrelPos)
were still not separable by call-graph or decomp, so they remain unresolved.

stdout: one pure JSON object. stderr: log.
"""

import json
import sys


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# No address is committed: every candidate examined this round either had its
# anchoring signal verified absent, was verified inline, or a concrete
# candidate decompiled to the wrong function. Per the hunt protocol
# ("prefer few correct over many shaky; an honest unresolved is better"),
# nothing is guessed.
FUNCTIONS: dict = {}

UNRESOLVED = {
    # ---- freighter ownership (feature/literal post-dates the legacy builds) ----
    "cGcPlayerFreighterOwnership::ResetPlayerFreighterBase":
        "1.13/1.24/1.38: string UI_FREIGHT_BASE_RESET_OWNER_OSD and imm64 "
        "0xA3784A062B2E43DB both verified ABSENT from all four legacy builds "
        "(by_string / imm-token scan) - the freighter-base-reset feature "
        "post-dates 1.38; no anchor exists.",
    "cGcPlayerFreighterOwnership::cGcPlayerFreighterOwnership":
        "1.13/1.24/1.38: ctor has no strings/imm; its only anchor is caller "
        "cGcGameState::cGcGameState (itself NOT_YET_FOUND) and it shares every "
        "seeded callee with the sibling ownership ctors - indistinguishable.",

    # ---- ship ownership unit (1.24/1.38): no anchor helper survives ----
    "cGcPlayerShipOwnership::Update":
        "1.24/1.38: distinctive callees (cGcPlacementArc::Render/Update/Reset, "
        "cGcScanner::CreateAndAddSimpleTimedScan, cGcScannedNodesList::RemoveNode) "
        "are NOT in the propagated seed and appear as no decomp literal. Filtering "
        "cGcGameState::Update's callees to large (>1500B), single-caller functions "
        "that call >=3 of their own address-neighbours yields TWO indistinguishable "
        "per-frame transform updaters per build (1.38 0x140771750/0x14078F250, "
        "1.24 0x14066B820/0x140670A70; both take a dt arg, no strings, identical "
        "named callees) - neither confirmable as the ship (vs sibling ownership) "
        "update by decomp, so not committable.",
    "cGcPlayerShipOwnership::UpdateMeshRefresh":
        "1.24/1.38: private helper of ::Update; the ::Update->UpdateMeshRefresh->"
        "cTkResourceDescriptor::GenerateInstance chain was traced from "
        "cGcGameState::Update and produced NO callee that reaches the mapped "
        "GenerateInstance, so neither ::Update nor this helper could be anchored.",
    "cGcPlayerShipOwnership::SpawnNewShip":
        "1.24/1.38: hint string 'cGcCustomisationComponentData' and imm64 "
        "0x5CB60F4300000004 verified ABSENT from all legacy builds; unit has no "
        "mapped neighbour so address-adjacency cannot enumerate it.",
    "cGcPlayerShipOwnership::DestroyShip":
        "1.24/1.38: no distinctive string/imm; would be reachable only via "
        "SpawnNewShip / the unresolved ownership unit - no mapped anchor.",
    "cGcPlayerShipOwnership::GetShipComponent":
        "1.24/1.38: 54-byte accessor calling cGcSpaceshipComponent::GetTypedComponent, "
        "which is itself unmapped and appears as no decomp literal; the common-callee "
        "of SSC::Update&UpdateLanding at that size is the cTkAttachmentPtr operator, "
        "not this - no unique anchor.",
    "cGcPlayerShipOwnership::cGcPlayerShipOwnership":
        "1.24/1.38: ctor imm64 0x2474290F0000000C verified ABSENT from all legacy "
        "builds; shares all seeded callees with cGcPlayerVehicleOwnership ctor - "
        "indistinguishable by call-graph.",
    "cGcPlayerVehicleOwnership::cGcPlayerVehicleOwnership":
        "1.24/1.38: shares all seeded callees with cGcPlayerShipOwnership ctor; "
        "no string/imm; caller cGcGameState::cGcGameState unmapped - indistinguishable.",

    # ---- ship HUD ctor ----
    "cGcShipHUD::cGcShipHUD":
        "all builds: no RTTI type-descriptor for cGcShipHUD in .data (vtable "
        "cannot be located that way) and the mapped ship-HUD methods "
        "(LoadData/ReadPlanetStats/RenderHeadsUp/RenderFlightHUD) are NOT stored "
        "in any vtable (no data pointer to them exists), so they give no vtable "
        "handle; no caller of cGcNGuiLayer::cGcNGuiLayer lies in the ship-HUD "
        "address window; caller cGcHUDManager::cGcHUDManager is unmapped.",

    # ---- spaceship component ----
    "cGcSpaceshipComponent::Eject":
        "all builds: verified inline/no standalone. In 1.09.1/1.13 the only "
        "caller of cGcVehicleCockpit::FinaliseExit is SSC::Update (DoExit+Eject "
        "inlined); in 1.24/1.38 the FinaliseExit->caller->Update chain resolves "
        "to a 1464/1201-byte per-frame camera-update helper (decompiled: "
        "time-delta FOV/camera-lag interpolation), not the ~498B Eject event.",
    "cGcSpaceshipComponent::GetVelocity":
        "all builds: 34-byte accessor (rigidbody GetLinearVelocity). "
        "cGcSpaceshipComponent::UpdateControlled (mapped, all builds) has no "
        "~34B callee wrapping a rigidbody getter - it is inlined into "
        "UpdateControlled / ThreadSyncPoint; no standalone function.",

    # ---- spaceship warp ----
    "cGcSpaceshipWarp::GetPulseDriveFuelFactor":
        "all builds: 84-byte stat getter (calls GetPrimaryItemForStat) called by "
        "cGcPlayerHUD::RenderIndicatorPanel (mapped). Verified inline: NO callee "
        "of RenderIndicatorPanel is also a caller of the mapped "
        "cGcPlayerState::GetPrimaryItemForStat, so the getter is inlined into "
        "the panel render - no standalone function to point at.",
    "cGcSpaceshipWarp::UpdatePulseDrive":
        "all builds: target_hints signature is ICF-folded with "
        "cGcPlayerExperienceDirector::UpdatePulseEncounters (strings/imm are the "
        "twin's). The pulse-drive/'PulseDriveStatus' logic in legacy lives inside "
        "a large SpaceshipComponent render function (e.g. 1.38 FUN_140F60180); no "
        "standalone cGcSpaceshipWarp::UpdatePulseDrive is separable.",

    # ---- spaceship weapons ----
    "cGcSpaceshipWeapons::GetCurrentShootPoints":
        "all builds: 139-byte getter (GetTypedComponent + cTkHmdOpenVR::GetInstance). "
        "cGcSpaceshipWeapons::Update was located (ShipShootShake/ShipLaserShake/"
        "OSD_OVERHEAT_SWITCH: 1.38 0x140F81250 / 1.24 0x140DCBC50 / 1.13 0x140C48360), "
        "but none of its ~100-200B callees decompiled to the shoot-point getter and "
        "the pattern is not consistent across builds - likely inlined; not committable.",
    "cGcSpaceshipWeapons::GetAverageBarrelPos":
        "all builds: 437-byte helper that calls GetCurrentShootPoints + "
        "ComputePhysRelMatFromNode. Via the located cGcSpaceshipWeapons::Update no "
        "callee pair (Y calls X) matched size/caller-count across 1.13/1.24/1.38, and "
        "the closest 1.24/1.13 candidate decompiled to an unrelated boolean check - "
        "not committable.",
    "cGcSpaceshipWeapons::GetHeatFactor":
        "all builds: 17-byte header (.h) inline accessor; not emitted as a "
        "standalone function in legacy builds.",
    "cGcSpaceshipWeapons::GetOverheatProgress":
        "all builds: 39-byte inline accessor; no call-neighbours seeded and no "
        "standalone function present.",
}


def main():
    log("[find_ship_space2] round-2 result: 0 committed, "
        f"{len(UNRESOLVED)} unresolved (all verified).")
    log("[find_ship_space2] new anchor (non-target) cGcSpaceshipWeapons::Update: "
        "1.38 0x140F81250, 1.24 0x140DCBC50, 1.13 0x140C48360.")
    json.dump({"functions": FUNCTIONS, "unresolved": UNRESOLVED},
              sys.stdout, indent=None)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
