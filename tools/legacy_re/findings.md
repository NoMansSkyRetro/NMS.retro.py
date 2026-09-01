# Identification log

How each entry in `nmspy/data/offsets.json` was found. Commands are `explore.py`
subcommands; all addresses assume the 0x140000000 preferred base. The original
"1.09.1" analysis turned out to be of the GOG binary (whose addresses do not
transfer); the Steam 1.09.1 build was re-analyzed from scratch, after which
`find_boot_set.py`, `harvest_name_literals.py` and `propagate_symbols.py` filled its
column (boot set: cGcApplication global 0x14160BA50, Update 0x1403DBBC0, cTkFSM
cluster at 0x140BC30D0..0x140BC32F0).

## The application FSM cluster

The legacy app is a state machine: `cGcApplication` derives from `cTkFSM`, and the app
FSM object is a **static global**, not heap-allocated as in the modern game. State IDs
are mixed-case strings (`AppBoot`, `AppCoreServices`, `AppGlobalLoad`, `AppLocalLoad`,
`AppView`, `AppShutdown`) unlike the modern all-caps IDs; 1.09.1 has no
`ModeSelector` state because game modes only arrived later.

Chain of identification, per build:

1. `grep <build> "FSM IGNORED"` — the log string
   `"\n - FSM IGNORED REQUEST : -> [%s], already transitioning to [%s]\n"` appears in
   every function that requests a state transition. Most call sites inline the
   request, but one hit is a tiny standalone function (74 bytes in 1.09/1.13, 72 in
   1.24/1.38): **`cTkFSMState::StateChange`** (`this` is a *state*, `this+0x18` its
   parent FSM). Its body writes the requested state ID into the FSM's pending-state
   slot (`fsm+0x18..0x30`) after checking it currently holds `FSM_NoState`. In 1.24+
   it gains the `lpUserData`/`lbForceRestart` parameters the modern signature has.
2. The 274-byte function immediately after it is **`cTkFSM::Construct`** (confirmed:
   takes the FSM, a state table, and the initial state ID `AppBoot`).
3. `grep` for the Construct address — its one external caller is
   **`cGcApplication::Construct`**: allocates the application data block
   (`0x8a5b60` bytes in 1.13, `0x8ae8e0` in 1.24, `0x841360` in 1.38), stores the
   pointer in a global (**`cGcApplicationData*`**), and constructs the FSM on the
   static **`cGcApplication`** global.
4. `grep "<app global> = "` — the static initializer that stamps the vtable pointer
   onto the app global. `vtable <build> <addr>` then lists the virtuals:
   slot 1 = `cTkFSM::Construct` (already known, cross-check), slot 2 (129 bytes in
   every build) = **`cTkFSM::Update`**.
5. `grep` for the `cTkFSM::Update` address — its one external caller is
   **`cGcApplication::Update`**, the per-frame main loop tick:
   `QueryPerformanceCounter`, two virtual queries, `cTkFSM::Update(&app, dt)`, then a
   virtual render call. Identical shape in every build.
6. `cTkFSM::Update`'s body reveals the FSM core: when the pending state ID differs
   from `FSM_NoState` it calls a 164-byte transition performer —
   **`cTkFSM::StateChange`**`(this, lNewStateID, lpUserData, lbForceRestart)` — which
   exits the current state (vtbl+0x28), swaps `this+0x10`, and enters the new one
   (vtbl+0x20). Every transition passes through it exactly once, so it is the hook
   for state-change notifications (the request path is inlined at most sites).

## Resulting addresses

| symbol | 1.13 | 1.24 | 1.38 |
|--------|------|------|------|
| cGcApplication::Construct | 0x1404ADF60 | 0x140561C80 | 0x140675900 |
| cGcApplication::Update | 0x1404B5BA0 | 0x14056B950 | 0x140680550 |
| cTkFSM::Construct | 0x140D4B320 | 0x140F0DC30 | 0x1410D3F50 |
| cTkFSM::Update | 0x140D4B460 | 0x140F0DDC0 | 0x1410D40E0 |
| cTkFSM::StateChange | 0x140D4B4F0 | 0x140F0DE50 | 0x1410D4170 |
| cTkFSMState::StateChange | 0x140D4B2D0 | 0x140F0DBE0 | 0x1410D3F00 |
| cGcApplication (global) | 0x1417F6C80 | 0x141A433F0 | 0x142033690 |
| cGcApplicationData* (global) | 0x1417F6CB8 | 0x141A43428 | 0x1420336C8 |

## Profiler name literals

Some functions wrap themselves in a profiler scope that copies their own name into a
local buffer, so the decompiled C contains e.g.
`strncpy(buf, "cGcGameState::LoadFromPersistentStorage", 0x80)`.
`harvest_name_literals.py` maps every such literal to its containing function
(skipping literals that appear in more than one function) and merges the result into
offsets.json — 22 functions in 1.13, 24 in 1.24/1.38, including
`cGcGameState::LoadFromPersistentStorage` / `WriteStateToStorage`,
`cGcPlanet::Generate`, `cGcPlanetGenerator::Generate` and
`cGcSimulation::Construct` / `Destruct`.

Notable: `cGcPlanet::Generate` is the function the 2023 Copernicus notes called
`NMS_PlanetSetupPerPlanet` (0x140BC5940 in 1.13); the profiler literal settles its
real name.

## cGcShipHUD

`cGcShipHUD::LoadData` is the one function referencing the
`UI\HUD\SHIP\HEADSUP.MXML` path string (via a small path-building helper in
1.24/1.38; grep HEADSUP, then take the helper's one caller). The two large sibling
functions in the same compilation unit are identified by their GUI element IDs:

- **RenderHeadsUp** references `MOON_TITLE`, `MOON_DESC`, `%PLANET%`,
  `SHIP_SCAN_PLANET` — confirmed by string-fingerprint match against the 4.13 PDB
  (propagate_symbols.py, 3 distinctive shared strings). An earlier manual guess had
  this the other way around.
- **RenderFlightHUD** (descriptive name, not from any PDB) references `SPEED`,
  `SPEEDBAR`, `JUMPBAR`, `SHIELD`, `TARGET_NAME`, `MINIJUMP`, ... — the per-frame
  speed/target flight display, a sibling with no matched modern name.

## Fleet hunt (2026-08-30)

A fleet of 15 agents (one per functional batch, see `out/hunt_batches.json`) worked the
NOT_YET_FOUND surface in parallel, each following `HUNTING.md` and shipping a
reproducible `finders/find_<batch>.py`. `merge_finder_results.py` validated and merged
every result (each address re-checked as a real function start). Net: **+170 addresses**,
raising upstream-surface coverage to 103 / 108 / 113 / 120 functions for
1.09.1 / 1.13 / 1.24 / 1.38.

Highest yields: planet_terrain (+25, anchored `cGcPlanet::Construct` off the 6-iteration
planet loop in `cGcSolarSystem::Construct`), solar_galaxy (+36, the galaxy classifier
cluster), filesystem_meta (+20, the FIOS2 syscall wrappers), engine_scene (+19, scene
-graph node accessors). interaction_trade returned +0 honestly: its anchor strings are
hashed in the legacy builds and its accessors are inlined.

Version-history facts the fleet established: 1.09.1 uses virtual-dispatch scene nodes
while 1.13+ use a struct-of-arrays node layout; `cTkDynamicGravityControl` was refactored
between 1.13 and 1.24 (its 64-slot free list removed); the scan-event runtime was
refactored after 1.38 (several sub-methods inlined); timed-goto HUD strings were added
between 1.13 and 1.24.

### Corrections applied after the fleet

The aggressive `min_votes=1` propagation had introduced a few mislabels, which the
agents surfaced and I verified before fixing:

- `cGcPlanet::UpdateWeather` was actually `cGcSky::Update` (identical addresses; the
  planet_terrain finder located Sky::Update independently). Moved the addresses to
  `cGcSky::Update`, reset `UpdateWeather` to NOT_YET_FOUND.
- `cTkFileSystem::GetInstance` pointed at a 180-byte path-string builder, not a
  singleton accessor. Reset to NOT_YET_FOUND.
- `Engine::AddGroupNode` was flagged as suspect but verified CORRECT on inspection
  (parent-resolve + add-child + `0x3ffff` invalid-handle sentinel, no FNV hashing).
  Kept.
- `nvg*` primitives were reclassified NOT_IN_THIS_VERSION -> NOT_YET_FOUND: the fleet
  found `cGcGalaxyMap::Data::RenderNVG` in all four builds, so the original
  single-string basis for "feature absent" no longer holds.

`make_target_hints.py` now flags identical-COMDAT-folded targets (`icf_folded_with`),
whose string/call hints are inherently ambiguous (e.g. `cGcSpaceshipWarp::UpdatePulseDrive`
folds with `cGcPlayerExperienceDirector::UpdatePulseEncounters`).

## Fleet round 2 (2026-08-30, with handles.py)

A second wave of 8 agents worked the anchor-rich batches using the new `handles.py`
cross-version toolkit (cached string/imm/call-graph indices; `by_string`, `port`,
`port_candidates`, `callers`/`callees`/`neighbours`). Net **+24 addresses**, raising
coverage to 112 / 120 / 124 / 130 for 1.09.1 / 1.13 / 1.24 / 1.38.

The round-2 win was searching *legacy* strings directly (not only porting the modern
4.13 hint set), which reached functions round 1 could not:
- `cGcPlayerCommunicator::Update` (all builds) via the drone anim strings `ATTRACT_OUT`.
- `cGcScanEvent::Update`/`CalculateMarkerPosition`/`UpdateInteraction` back-filled in
  1.09.1/1.13 via the version-stable `SIGNAL_COMPLETE` anchor.
- `Engine::ShiftAllTransformsForNode` (1.13/1.24/1.38) — an NMS-Newton engine call.
- `Engine::GetNodeNumChildren`, `cGcSky::UpdateSunPosition`, `cGcNGuiLayer::GetGraphic`.

Verified negatives (well-established, not forceable):
- `cGcMarkerPoint::IsEqual` and the whole marker cluster: the struct diverged too far
  from 4.13 for any body fingerprint, and nothing in the marker unit is anchored.
- The solar-system generator sub-functions, orbit enter/leave, weather/clouds/gravity
  split, and terrain-editor Flatten/Stroke split are all inlined or postdate 1.38.

Reusable struct intel from this round: the scene-node manager holds tree structure in
a struct-of-arrays at `mgr+0x78` (stride 0x14): +0 numChildren (`& 0x7fffffff`),
+4 parent TkHandle, +8 first-child index, +0x10 next-sibling index.

Off-surface anchor located for future rounds (not one of the 331):
`cGcSpaceshipWeapons::Update` via `ShipShootShake`+`ShipLaserShake`+`OSD_OVERHEAT_SWITCH`
(1.13 0x140C48360, 1.24 0x140DCBC50, 1.38 0x140F81250).

## Source-file adjacency (locate_by_source.py)

The 4.13 PDB records a source path for 81.5k/85.4k functions
(`reference_symbol_db.json`), and MSVC emits one .cpp's functions contiguously in
source-line order. So an unmapped target's nearest already-mapped same-file neighbours
bracket a small legacy address window it must fall inside. `locate_by_source.py` emits
those windows (`out/source_ranges.json`) as leads and auto-commits the rare case where
the window holds exactly one function.

At current coverage the reach is limited (most targets have no mapped same-file anchor
on both sides), but it produced a clean win: **cGcPlayerHUD::RenderIndicatorPanel in
1.09.1 = 0x14048DBF0**, which round 2 had called absent. Three signals agreed: it is
the sole function between the mapped RenderCrosshair and RenderWeaponPanel in
gcplayerhud.cpp, it shares RenderWeaponPanel's caller (the HUD render dispatcher
0x14048c440), and it renders indicator icons (`ICON%d`/`ICONS`/`TECH1` loop) rather
than the NEXT-era `JETPACK`/`STAMINA` the later builds show. The same tool confirmed
`Engine::GetNodeParent` is inlined in all four builds (its bracket window is empty).

The windows tighten automatically as coverage grows, so re-running this after future
rounds will surface more single-function locks.

## Live Ghidra (ghidra_live.py)

`ghidra_live.py` opens a legacy build's already-analyzed Ghidra project read-only via
pyghidra (the mechanism OpenNMS uses) and exposes the queries the static SQLite decomp
cannot: the real ReferenceManager (data, computed, and indirect/vtable refs, not just
E8/E9 direct calls) and the decompiler on demand.

    python ghidra_live.py smoke 1.38
    python ghidra_live.py xrefs 1.38 0x140680550
    python ghidra_live.py decompile 1.38 0x140f81250

Proven value: it finds a DATA reference to cGcApplication::Update from 0x1424f32e8 (a
function pointer stored in a data structure) that the E8/E9 call-edge scan misses.

First use, the marker cluster: driving real callees of the mapped
cGcScanEvent::UpdateInteraction showed that in this legacy build it does NOT call the
marker-list add/remove functions the way 4.13 does (its similar-looking callees are a
scan-state update pair, not TryAddMarker/RemoveMarker). So cGcMarkerPoint::IsEqual is
still not reachable from current anchors even with live Ghidra: the scan-event/marker
code was restructured between these builds and 4.13. The cluster needs a fresh anchor
(e.g. the marker vector's element size 0x30 seen in the reset loop at 0x1406C27A0 in
1.38) or manual RTTI/vtable work, not anchor-chasing from what is mapped now.

## Hand-golf with live Ghidra (decompiler-in-the-loop)

Combining the source-adjacency range hints with `ghidra_live.py` (decompile + real
xrefs) is the productive manual workflow: the ranges narrow a target to a handful of
candidates, then the decompiler confirms one.

- **cGcGameState::ComputeWarpCapability** — mapped in all four builds
  (1.09.1 0x14041D070, 1.13 0x1405320D0, 1.24 0x140641DF0, 1.38 0x14075BD50). The
  source-file bracket gave 4-6 candidates per build; the winner in 1.38 is called by
  the mapped cGcGalaxyMap::Data::DoSolarPopup AND references "Hyperdrive"; 1.13/1.24
  confirmed by the same "Hyperdrive" idiom; 1.09.1 (where that debug string is
  stripped) confirmed by the matching `WarpCapabilityResult*(this, result*, float, ...)`
  struct-return signature, size, and caller count.

Its callees (GetHyperdriveFuelUse, QueryAmountInAllInventories, GetPrimaryItemForStat,
ComputeWarpEngineJumpDistanceInLightyears) turned out NOT to be in upstream's 331, and
the one that is (cGcPlayerEnvironment::IsOnboardOwnFreighter) is inlined here, so the
cascade stopped at one function.

### Renames are rare; naming was stable 2016-2017

`harvest_version_names.py` broadened the profiler-literal harvest (any namespace) and
compared each located function's actual name across builds. Result: essentially no
renames among our surface. The one alias is `cGcGameState::OnSaveProgressCompleted`,
which is really `WriteStateToStorage` in every legacy build (modern split a distinct
save-completed callback out later). offsets.json now carries this as an `_aliases`
entry, and `_names` documents per-version names where they differ from the key.

## The 4.13 OpenNMS project as a resource

`E:\OpenNMS` is the 4.13 matching-decompilation pipeline (byte-perfect C++
reconstruction). It is a different goal from ours (locate vs reconstruct), but its data
is useful here: `NMS413_GHIDRA_ANALYSIS\symbol_db.json` and `decomp\decomp.db` carry
the 4.13 call graph, source paths, types, and `/OPT:ICF` fold groups — richer than
`reference_symbol_db.json`. The clear next lever for the anchor-starved remainder is
**live Ghidra on the legacy projects** (`E:\NMSLegacy_Decomp\NMS*_GHIDRA_PROJ`) via the
Ghidra MCP bridge: real data xrefs and the decompiler, which the static SQLite decomp
databases (and our E8/E9 call-edge scan) cannot provide. That is a manual RE session,
not an automated sweep.

## Triage + port backfill (2026-08-30)

After the automated string/call-graph sweep saturated (fleet yields fell 170 -> 24), a
consolidation pass rather than another blind sweep:

- **Port backfill.** `finders/find_ports.py` ports every partially-mapped surface
  function (located in >=1 build, NOT_YET_FOUND in another) from each build where it is
  known, accepting a slot only when every resolving source agrees and the merge tool
  re-validates it as a function start. Net **+9 addresses**: `cGcGalaxyMap::Data::DoSolarPopup`
  and `cGcPlanetGenerator::GenerateCreatureSpawnData` completed in all four builds from
  their 1.38 anchor, `cGcFrontendPageDiscovery::DoDiscoveryView` to 1.13/1.24, and
  `cGcPlayerHUD::Update` back-filled in 1.09.1. This dropped partials 18 -> 13; the
  survivors are the hard 1.09.1/1.13 hops where `port()` abstains (six-year token/
  call-graph decay), plus `cTkDynamicGravityControl::cTkDynamicGravityControl` which
  needs 1.24/1.38 because the gravity control was refactored after 1.13.

- **Absence reclassification.** The 86 anchor-less NOT_YET_FOUND functions were triaged:
  they are overwhelmingly present-but-inlined engine/utility code (cEg*, cTk*, Engine,
  nvg, core cGc gameplay), not absent features. The genuinely-absent features were
  already marked in earlier rounds. Six exceptions whose `_unresolved` note already
  concluded the feature postdates the build were promoted NOT_YET_FOUND -> NOT_IN_THIS_VERSION
  and recorded in `build_full_surface.py`'s new per-function `EXACT` table (prefix rules
  can't express a single late method in an otherwise-old class): `cGcPlayer::GetDominantHand`
  (VR/OpenVR, Beyond 2.0), `cGcBuilding::DestroyIntersectingVolcanoes` (volcano landmarks),
  `cGcScanEvent::UpdateSpaceStationLocation` (settlements), `cGcPlayerFreighterOwnership::ResetPlayerFreighterBase`
  (freighter bases, NEXT 1.5), and the 1.09.1 slots of `cGcFrontendPageClaimBase::DoBaseClaimOptions`
  and `cGcQuickActionMenu::TriggerAction` (base/quick-action UI predates Foundation 1.1).
  Net +17 NOT_IN slots. The lesson for future rounds: the anchor-less bucket is not
  hiding ghosts to prune, so "remaining that exists" is already an honest count.

- **Marker anchor tracked.** `cGcMarkerPoint::IsEqual` (an NMS-Newton anchor, not in
  upstream's 330) had no row at all; added off-surface as NOT_YET_FOUND carrying the
  documented blocker so it stops being invisible to the tooling.

Coverage after this round (surface addresses located): **1.09.1 133, 1.13 142, 1.24 148,
1.38 151**; NOT_YET_FOUND remaining 175 / 178 / 182 / 185. `verify_offsets.py` passes.

## Decompiler-in-the-loop fleet (2026-08-30)

The string/imm/name sweeps and porting are exhausted; what remains has no distinctive
tokens, so the only handles are call-graph position and *behaviour*. New pipeline:

1. `ghidra_live.py dossier 1.38` opens the analyzed project once and, for each of the 54
   mapped anchors that a still-missing target hangs off, dumps the anchor's decompiled
   body plus every callee (real ReferenceManager edges) with size, named grandchildren,
   and a decompiled body — 1,108 candidate functions.
2. `fleet_slice.py <build> <targets>` turns that into a focused per-target view (4.13
   profile + anchor context + size-banded candidate bodies).
3. A 14-agent workflow (`out/match_workflow.js`): 7 match agents read their slices and
   propose a 1.38 address per target by signature/size/behaviour; a paired adversarial
   agent tries to refute each. Only matches that survive verify are kept.
4. `finders/find_anchor_matches.py` commits the confirmed 1.38 addresses and ports them
   sideways; `merge_finder_results.py` re-validates every address as a function start.

Result on 68 anchored targets: **11 located in 1.38, 0 rejected, 57 classified as not
separately present** (21 inlined into the anchor, 25 no callee of matching shape/size,
3 feature postdates 1.38, plus folded/other). I decompile-reviewed the tiny/odd and
medium-confidence matches by hand before committing (e.g. `cGcInteractionData::SetDefaults`
0x14028A9D0 is a 24-byte zero-init writing -1.0f at +0x1c; `cGcInteractionComponent::GiveReward`
0x140CA49F0 has the exact `(this, option&, bool, bool)->bool` shape and reward-array loop).

The 11: cGcSpaceshipWarp::UpdatePulseDrive (via the SENTINELS_EVADED string, ported to
1.13/1.24), cGcPlayerWanted::Update, cGcFrontendPagePortalRunes::CheckUAIsValid (1.38-only,
portals postdate the older builds), cGcMarkerList::TryAddMarker (its body inlines
cGcMarkerPoint::IsEqual — the marker-identity compare the cluster was blocked on),
cGcInteractionData::SetDefaults, cTkAudioManager::Play_attenuated,
cGcPersistentInteractionsManager::LoadGalacticAddressBuffers, cGcInventoryStore::Add,
cGcInteractionComponent::GetInteractionData, cGcInteractionComponent::GiveReward,
cGcPlayer::CheckFallenThroughFloor.

**Empirical ceiling:** even among targets that *have* a mapped call-anchor, only ~16%
were separately present in 1.38; the rest are inlined/fused. This confirms 100% *located*
is impossible and 100% *classified* is the real goal.

### Cross-build port of the 1.38 finds (deterministic fingerprint match)

Ten of the 11 exist in all builds but came in 1.38-only. A second fleet on the older
builds was starved (dossier bodies too thin, plus a session-limit outage), so the port
was done deterministically instead: `handles.py port_candidates` gives ranked leads from
the 1.38 address, filtered to a size band, and `match_crossbuild.py` fingerprints each
candidate's decompiled body against the 1.38 original (return kind, param count, shared
named library calls, shared literals/constants, size ratio) and commits only a clear
winner. Discriminators that settled the hard ones: `SENTINELS_EVADED` (UpdatePulseDrive
1.09.1), the `AK::SoundEngine::PostEvent` pair + exact 120 B (Play_attenuated), the
`+0x238` reward-array offset + `TECHWEAPON` (GiveReward, all three older builds), and the
`GetCurrentThreadId`+`Sleep` mutex guard that picked CheckFallenThroughFloor 1.13
0x140B5BB30 over the closer-in-size but signature-wrong 0x140B729E0. Net **+13 addresses**.
`cGcInteractionData::SetDefaults` (a 24 B stub, inlined in the older builds),
`cGcInteractionComponent::GetInteractionData` (the modern global data-slots at DAT+0x54e0
don't exist in legacy), and `cGcMarkerList::TryAddMarker` (no matching 0x140-stride marker
vector) were left classified rather than force-matched.

**Session total (2026-08-30):** located +6 / +9 / +9 / +11 (1.09.1 / 1.13 / 1.24 / 1.38)
to **136 / 148 / 154 / 162**, +17 NOT_IN reclassifications, and the whole "should exist
but unmapped" surface (173 functions) is 100% classified with a recorded blocker.

## Struct layout so far

- `cTkFSM`: `+0x10` current `cTkFSMState*`; `+0x18` pending-state
  `cTkFixedString<0x10>` (holds `FSM_NoState` when idle); `+0x28` pending user data;
  `+0x30` force-restart flag. State objects store the timestamp they were entered at
  `+0x20` and their parent FSM at `+0x18`.
- The app state IDs (`dumpstr` around the `AppBoot` string): `AppBoot`,
  `AppCoreServices`, `AppGlobalLoad`, `AppLocalLoad`, `AppView`, `AppShutdown`,
  `YouAreDead`, and from 1.13 on `ModeSelector`. MixedCase, one-to-one with the
  modern all-caps IDs.
- The app data block (`cGcApplicationData*` global) is the legacy analogue of the
  modern `cGcApplication::mpData`; sub-objects live at fixed offsets inside it
  (e.g. `+0x30` referenced in every build's Construct).

### Runtime-class field offsets (exe RE, `field_evidence.py` + adversarial verify)

Offsets by build `1.09.1 / 1.13 / 1.24 / 1.38`, written into `nmspy/data/types.py`
`_vfields_`. Derived from each class's ctor/Construct/user methods in the cached decomp
(`tools/legacy_re/field_evidence.py`), then adversarially verified; guarded by
`tools/legacy_re/test_runtime_fields.py`.

- `cGcPlanet`: `miPlanetIndex` (int) `0x50 / 0x50 / 0x50 / 0x58`; `mPlanetGenerationInputData`
  (embedded) `0x2F00 / 0x3010 / 0x3010 / 0x3550`; `mRegionMap` (embedded `cGcTerrainRegionMap`,
  ctor'd in place, used by `SetupRegionMap`) `0x2FC0 / 0x30F0 / 0x30F0 / 0x3630`; `mNode`
  (`TkHandle`, ctor sentinel `0x3FFFF`, fed to the node-transform call in `Generate`)
  `0xE7CE8 / 0x12E318 / 0x12E318 / 0x12E868`; `mPosition` (`Vector3f`, the three floats +w=1.0
  written in `Generate`) `0xE7D00 / 0x12E330 / 0x12E330 / 0x12E880`. `mpEnvProperties`,
  `mPlanetDiscoveryData` not yet located.
- `cGcShipHUD`: `mHeadsUpGUI` (embedded `HEADSUP.MXML` GUI, named from `LoadData`'s MXML loads)
  `0x22930 / 0x23030 / 0x23030 / 0x23AD0`; `miSelectedPlanet` (int, from `RenderHeadsUp`)
  `0x212A8 / 0x21998 / 0x21998 / 0x22438`.
- `cGcSolarSystem`: `maPlanets` (base of the 6 inline `cGcPlanet`, from the 6-iter `Construct`
  loop) `0x16B0 / 0x17A0 / 0x17A0 / 0x1C30`.
- `cGcApplication` (static singleton, base = the object passed to `cTkFSM::Construct`/`Update`:
  `&DAT_14160BA50 / &DAT_1417F6C80 / &DAT_141A433F0 / &DAT_142033690`): `mpData`
  (`cGcApplicationData*`) at base `+0x38` in all builds; `muPlayerSaveSlot` (int) at `+0x40`
  (1.38 only so far).
- `cTkDynamicGravityControl::maGravityPoints`: **not accepted.** The ctor is now located in
  all four builds (below) and the pool structure is understood (0x40 elements, stride 0x1318,
  free-list at `+0x4C600`/`+0x4C700`, count at `+0x4C800`), but `maGravityPoints` at `+0x0`
  is just "the pool is the object" and `GetGravity`/`UpdateGravityPoint` (which would pin the
  semantic offset) are inlined with no standalone start. Left unmapped.

### Round 2 — blocker functions located, more fields (same fleet method)

New functions located (validated function starts, in `offsets.json`; `verify_offsets.py` passes):

- `cGcMarkerPoint::cGcMarkerPoint` + `::Reset`, **all four builds** (the marker cluster,
  previously "diverged too far"): ctor sits right before Reset, tail-calls it; Reset does the
  default-init (`strncpy(this+0x38, "", 0x40)` name-clear, `0x3FFFF` bitfield sentinels at
  `+0x78`/`+0x7C`, `w=1.0` triplets). Found by the tiny-ctor→Reset adjacency.
- `cTkDynamicGravityControl::cTkDynamicGravityControl`: **completed** (1.24 `0x1405ADB10`,
  1.38 `0x1406C4590`; 1.09.1/1.13 already had it). Found by the unique `0x4C600`/`0x4C800`
  class-pool init signature.
- Off-surface anchors: `cGcEnvironment::UpdatePlayerEnvironmentState` (all 4; sole referencer
  of its debug string), `cGcApplication::SetPlayerSaveSlot` (1.24/1.38), `cTkAABB::IsPositionInBox`
  (all 4; the inlined `GetGravity`'s sole callee).

New field offsets (in `types.py`, guarded by `test_runtime_fields.py`):

- `cGcNGuiText::mpTextData` `+0x60` (all builds, from `EditElement`).
- `cGcShipHUD::mbSelectedPlanetPanelVisible` (4-byte flag right after `miSelectedPlanet`)
  `0x212AC / 0x2199C / 0x2199C / 0x2243C`.
- `cGcMarkerPoint::mCustomName` (`cTkFixedString<0x40>`) `+0x38` (all builds).
- `cGcAlienPuzzleEntry`: `Id` `+0x0`; `Options` `0x420 / 0x420 / 0x420 / 0x4B0`.

Honest negatives (not stored / inlined, recorded so they are not re-hunted blindly):

- `cGcPlanet::mpEnvProperties`, `mPlanetDiscoveryData`: **no stored member** in these builds.
  The env/weather stats are read inline by `cGcEnvironment::UpdatePlayerEnvironmentState` off
  the nearest planet; `Generate` takes `cGcDiscoveryData const&` but never copies it into a
  field. These are modern-only pointers.
- `cGcApplication::muPlayerSaveSlot`: **1.38-era**; `SetPlayerSaveSlot`/`GetRespawnReason`
  show 1.24 has only the mode field (`base+0x40`), and 1.38 inserts the slot at `base+0x40`
  (mode moves to `+0x44`). `mbPaused`: no dedicated pause bool found on the singleton.
- `GetGravity`, `UpdateGravityPoint`, `cGcMarkerPoint::IsEqual`,
  `cGcInteractionComponent::GetPuzzle`: **inlined**, no standalone function start in any build.
