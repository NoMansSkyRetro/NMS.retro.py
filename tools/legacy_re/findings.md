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
