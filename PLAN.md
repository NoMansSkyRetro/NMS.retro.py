# NMS.retro.py — Legacy Retargeting Plan

Retarget NMS.py from the modern game (4.x, pattern-scanned, PDB-derived structs) to four
frozen Steam builds: **1.09.1, 1.13, 1.24, 1.38**.

## Guiding insight

Upstream NMS.py uses byte-pattern signatures because the modern game keeps updating.
Our four targets will never change again. That flips the whole design: **static RVAs
extracted once from the Ghidra databases beat pattern scanning** on every axis
(reliability, startup speed, maintenance). pyMHF already supports this natively via
`function_hook(offset=...)`, so no framework changes are needed.

## 1. Version detection: PE TimeDateStamp

No hashing needed. The four builds have distinct 4-byte PE header timestamps:

| Version | Size (bytes) | TimeDateStamp | Build date (UTC) |
|---------|-------------:|---------------|------------------|
| 1.09.1  | 23,306,752 | `0x57FF70CA` | 2016-10-13 |
| 1.13    | 25,201,152 | `0x584983DE` | 2016-12-08 |
| 1.24    | 27,675,648 | `0x58D42A08` | 2017-03-23 |
| 1.38    | 29,963,264 | `0x59CE2F3C` | 2017-09-29 |

Advantages over the NMSVersionDll SHA1 approach:

- Reads 4 bytes instead of hashing a 22–30 MB file.
- Immune to SteamStub packing (the PE header survives packing, so packed and unpacked
  copies of the same build map to the same version).
- Works on both the on-disk file and the in-memory mapped image.
- Extensible: add GOG builds later as new table rows.

Implementation: `nmspy/versions.py` reads the timestamp from
`pymhf.core._internal.BINARY_PATH` at import time and exposes `CURRENT_VERSION` (an
enum: `V109`, `V113`, `V124`, `V138`). Unknown timestamp = clear startup error naming
the timestamp so new builds are easy to add. Keep the NMSVersionDll SHA1 table as an
offline cross-check tool only.

## 2. Addressing: per-version RVA tables

Restructure `tools/data.json` from one signature per function to per-version offsets
(RVAs relative to the `0x140000000` preferred base, matching Ghidra addresses):

```json
{
  "name": "cGcApplication::Update",
  "mangled_name": "?Update@cGcApplication@@QEAAXXZ",
  "offsets": { "1.09.1": "0x14059c2a0", "1.13": "0x1405b1f80", "1.24": null, "1.38": null }
}
```

`null` = not yet located for that version. A tiny helper resolves the offset for
`CURRENT_VERSION` and feeds it to the decorator:

```python
@function_hook(offset=offset_for("cGcApplication::Update"))
def Update(self, this): ...
```

Decorator arguments evaluate at import time, and the version is known before
`nmspy.data.types` loads, so this needs no runtime dispatch. When `offset_for` returns
`None` the hook is registered as disabled with a log warning; mods that try to use it
get a clear "not available in 1.24" error instead of a crash. This keeps **one API
surface across all four versions**, with only the data varying.

Mods get a version-gating API: `nmspy.versions.CURRENT_VERSION` for branching, plus a
`@requires_version(...)` decorator that disables a hook/mod outside its supported range.

## 3. Symbol identification pipeline (the bulk of the work)

Function RVAs must be found per version. Current state of the decomp DBs
(`E:\NMSLegacy_Decomp\*\decomp.db`):

| Build | Functions | Named (non-`FUN_`) |
|-------|----------:|-------------------:|
| 1.09.1 | 38,294 | 1,108 — includes real `cGc*` symbols |
| 1.13 | 40,049 | 1,333 — mostly library symbols |
| 1.24 | 43,288 | 1,351 — mostly library symbols |
| 1.38 | 46,612 | 1,351 — mostly library symbols |

Pipeline (`tools/propagate_symbols.py`, offline, reads the four SQLite DBs):

1. **Seed** from 1.09.1's named `cGc*` functions, the reconstructed 1.09.1 source and
   `reference_symbol_db.json` in `E:\AI_NMS_DISASM\NMS1091_GHIDRA_ANALYSIS\`, and the
   hardcoded 1.13 names in the Copernicus tooling (`step_2_apply_names.py`).
2. **Propagate** names across adjacent versions by string-literal matching (each
   `raw_decomp` carries its referenced strings — FSM state IDs, mbin paths, debug text
   are highly distinctive) with call-graph neighbourhood as a tiebreaker.
3. **Emit** confirmed `name → RVA` rows into `data.json`; ambiguous matches go to a
   review list, never silently into the data.

Start with the minimal boot set (cGcApplication Construct/Update, cTkFSM
Construct/Update/StateChange, cGcApplicationGameModeSelectorState, save/load entry
points), then grow function-by-function as mods need them — the same incremental model
upstream uses.

## 4. Structs: regenerate, don't reuse

`nmspy/data/exported_types.py` (1.8 MB) is generated from the 4.13 PDB. 1.x layouts are
substantially different; reusing it would produce silently-wrong field reads. Plan:

- **Metadata/Globals structs** (everything mbin-backed): generate from historical
  MBINCompiler/libMBIN releases matching each game era (the project has tags back to
  the 1.x days; 1.3x is well covered). Adapt `tools/create.py` to consume those
  definitions per version.
- **Runtime classes** (cGcApplication, cGcSimulation, cGcPlayer, cGcGameState, ...):
  reverse from the Ghidra DBs, 1.09.1 first since it has real names, then diff forward.
- Use pyMHF's `partial_struct` + explicit `Field(type, offset)` and define **only
  verified fields**. Where an offset moved between versions, resolve it through the
  same per-version data mechanism as function offsets.
- `nmspy/common.py`'s `GameData` property chain (application → simulation → player)
  stays as the stable mod-facing API; only the underlying offsets change.

Trim the `Globals` class in `nmspy/globals.py`: many modern globals
(GcFishingGlobals, GcSettlementGlobals, GcFleetGlobals, ...) don't exist in 1.x.
Per-version global lists live in the same versioned data.

## 5. Globals resolution

The runtime `.rdata`/`.text` scan in `nmspy/globals.py` assumes modern binary
conventions. For frozen builds, bake **static global RVAs per version** into the data
file (extracted once via the decomp DBs / a one-off run of the existing scan logic
against each exe). Demote the scanner to an offline extraction tool in `tools/`.

## 6. Launch configuration

`nmspy/pymhf.toml` launches via `steam_gameid = 275850`, which only starts whatever
version Steam currently has installed. The legacy copies live in standalone folders
(`E:\NMSLegacy\no_mans_sky_v<ver>\Binaries\NMS.exe`), so document launching by exe
path in the pyMHF config, one config per installed version. `exe = "NMS.exe"` name
matching is unchanged.

## Target mod: NMS-Newton

The concrete goal driving coverage is running
[NMS-Newton](https://github.com/monkeyman192/NMS-Newton) (moving planets) on all four
builds. Its nmspy API surface defines the Phase 2/3 work list:

Functions to locate per build:

| symbol | notes |
|--------|-------|
| cGcApplication::Update | done (main loop) |
| cTkStopwatch::GetDurationInSeconds | or substitute: cTkFSM::Update already carries the frame dt |
| cGcPlanet::SetupRegionMap | planet init; caches planet + node handle |
| cGcSolarSystem::OnEnterPlanetOrbit / OnLeavePlanetOrbit | orbit state tracking |
| cGcShipHUD::RenderHeadsUp | orbital-period HUD text |
| cGcNGuiLayer::FindTextRecursive | called directly to find the HUD text element |
| cGcMarkerPoint::IsEqual | marker stability while planets move |
| cTkDynamicGravityControl::Construct (or ctor/GetGravity) | gravity singleton capture |
| cGcApplicationLocalLoadState::GetRespawnReason | "loaded enough" signal |
| cGcGameState::LoadFromPersistentStorage / OnSaveProgressCompleted | save integration |
| cGcPlayerBasePersistentBuffer::LoadGalacticAddress | base-building objects; 1.13+ only (1.09.1 predates bases) |
| Engine::ShiftAllTransformsForNode | called to move a planet's scene node |
| cGcRewardManager::GiveGenericReward | interactions.py toggle |
| cGcInteractionComponent::GetPuzzle | interactions.py station-core dialogue |

Structs/fields to map: cGcPlanet (mPosition, miPlanetIndex, mNode, mRegionMap,
mpEnvProperties, generation seed, discovery UA), cGcSolarSystem (maPlanets, system
data PlanetOrbits), cGcApplication (mbPaused, muPlayerSaveSlot, data chain to
simulation / game state / player environment), cGcPlayerEnvironment
(miNearestPlanetIndex, mfDistanceFromPlanet), cTkDynamicGravityControl
(maGravityPoints), cGcShipHUD (mHeadsUpGUI.mRoot, miSelectedPlanet,
mbSelectedPlanetPanelVisible), cGcNGuiText (mpTextData.Text), cGcMarkerPoint
(mCustomName), basic Vector3f/TkHandle (already build-independent).

### Compatibility gating lives in the framework, not in mods

Mods like Newton should run unmodified; NMS.retro.py absorbs the per-build
differences. The rules:

- `types.py` declares the FULL API surface mods use, on every build, so mods always
  import and load. Availability is data-driven from `offsets.json`.
- Every function upstream NMS.py supported has a row in `offsets.json`; a slot
  without an address carries a flag: `NOT_YET_FOUND` (exists, nobody has located it)
  or `NOT_IN_THIS_VERSION` (the feature postdates the build, with a `_note` giving
  the release history). `nmspy.data.offsets.availability(name)` exposes this to code.
- A hook with no address in the running build is disabled: its detours never fire
  (one warning at mod load, worded from the flag and note).
- Calling an unmapped game function warns once and returns None instead of raising.
- Struct fields are declared with per-version offsets (`_vfields_` +
  `versioned_struct`); a field not mapped in the running build reads as None with a
  one-time warning. Fields for features a build predates (e.g. base building before
  1.13) simply have no offset there.
- `gameData` accessors return None whenever their chain is unavailable, matching the
  `if x is not None` guards mods already write.
- Where legacy lacks a modern function but has an equivalent, `offsets.json` aliases
  it (e.g. `cGcGameState::OnSaveProgressCompleted` -> `WriteStateToStorage`) so the
  modern hook name keeps working.

## Phases

1. **Plumbing.** `versions.py` (timestamp detection), `offset_for()` helper,
   restructured `data.json`, hook-disabled-when-null behaviour. Exit criteria: pyMHF
   injects into all four versions, logs the detected version, and one hooked function
   (from the 1.09.1 named set) fires in at least one version.
2. **Symbol propagation.** `tools/propagate_symbols.py`; core boot set located in all
   four versions; `data.json` populated.
3. **Struct regeneration.** Minimal viable chain (application → game state → player)
   plus a handful of Globals per version; libMBIN-based generator for metadata structs.
4. **Smoke-test internal mod** (logs boot FSM states, player position once in-game)
   run against all four versions; port/prune `example_mods` and `_internal_mods`.
5. **Iterate coverage** on demand, keeping the per-version data files as the single
   source of truth.

Deletions are deliberate and lazy: `broken_patterns.txt`, pattern-update tooling
(`update_from_data.py`'s signature rewriting), and modern-only data get removed as
each replacement lands, not in a big-bang purge — `exported_types.py` in particular
stays until its per-version replacement imports cleanly.
