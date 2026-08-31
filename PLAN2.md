# NMS.retro.py — Phase 2 Plan (completion)

Phase 1 (PLAN.md) built the retargeting framework: version detection, per-build offset
data, the `versioned_struct` mechanism, and the RE toolkit. This plan takes it to the
finish line: **NMS-Newton running on all four builds (1.09.1 / 1.13 / 1.24 / 1.38)**.

## Where we are

- **Functions:** 138 / 148 / 154 / 162 located of the ~330 upstream surface, and the
  "should-exist but unmapped" remainder (173) is **100% classified** — every slot is an
  address, `NOT_IN_THIS_VERSION`, or `NOT_YET_FOUND` with a decompiler-confirmed blocker
  (`tools/legacy_re/findings.md`). The empirical ceiling: ~16% of anchored targets are
  separately present in these builds; the rest were inlined/folded by the 2016-2017
  compiler and cannot be hooked.
- **Structs:** authoritative *effective* per-build layouts dumped from
  [MBINCompiler.retro](https://github.com/NoMansSkyRetro/MBINCompiler.retro) for all four
  builds — **1.09.1 (535), 1.13 (651), 1.24 (714), 1.38 (905)** templates. `gen_structs.py`
  merges them into per-build `versioned_struct` classes (per-build types), and the ~38
  metadata globals `nmspy/globals.py` maps are wired in via the generated
  `nmspy/data/mbin_globals.py`; `tools/mbin/test_layouts.py` verifies every field against
  libMBIN's offset in all four builds. **The 1.13 gap is closed** (no released MBINCompiler
  tag reached Foundation; MBINCompiler.retro's re-derived `V1_13` set does).
- **New lever found:** every metadata struct GUID is a unique imm64 constant in the code
  (68/68 sampled hit, one owner function each), so the MBIN work yields ~890 named
  metadata-loader anchors per build, plus id-string TkID hashes.

## Two facts this plan relies on

1. `versioned_struct` (`nmspy/data/offsets.py`) is the multi-version layer; its per-build
   `_vfields_` offset dicts are the data the MBIN pipeline produces. `exported_types.py`
   (4.13, single-version) is used only by `globals.py` and gets replaced for mbin-backed
   structs.
2. MBIN GUIDs and id-string TkID hashes are era-correct per build and appear as imm64
   anchors, unlike the 4.13-only hint set the earlier hunts used. This reaches the ~33
   metadata-shaped unmapped functions and their call-graph neighbours.

## Workstreams

### A. Struct layer: complete and integrate — **largely done**

1. ~~**1.13 layout.**~~ **Done** via MBINCompiler.retro's `V1_13` set + `dumplayout`.
2. **Verify** a handful of generated offsets against the exe per build (confirm libMBIN's
   serialized layout equals the in-memory C++ layout we hook). Field offsets already match
   libMBIN by construction (`test_layouts.py`); still spot-check 2-3 container-bearing
   structs against the running exe. **Open.**
3. ~~**Integrate.**~~ **Done for the globals layer:** `gen_structs.py globals-module` emits
   `nmspy/data/mbin_globals.py` (per-build `versioned_struct` globals, 4.13 fallback for the
   13 modern-only/runtime-composed ones), and `globals.py` imports it instead of
   `exported_types.py`. Retiring `exported_types.py` entirely waits on wider coverage (A.4)
   and the runtime classes (workstream C, which it does not cover).
4. ~~**Per-version types.**~~ **Done.** `versioned_struct` now takes a `{version: ctype}`
   spec; `gen_structs.py` emits per-build type + offset so restructured structs
   (`GcEnvironmentGlobals` 0x330→0x460) generate exactly. Widening past the ~38 mapped
   globals is just running `gen_structs.py <Name>` for the structs a mod needs.
5. Trim the modern-only `Globals` (PLAN.md §5): `GcFishingGlobals`, `GcSettlementGlobals`,
   `GcFleetGlobals`, ... are already routed to the 4.13 fallback (absent from every 1.x
   layout); drop them from `globals.py` outright when convenient.

### B. Function layer: mine the MBINs for anchors

1. **GUID -> loader map.** Harvest every MBIN header GUID per build, find its unique imm64
   owner (`handles.py` imm64 index), and record the ~890 named metadata-loader functions
   as anchors (off-surface, in `offsets.json` or a side table).
2. **Id-string TkID anchors.** Decompile the metadata *tables* (not just globals) to EXML,
   harvest their id strings, FNV-1a hash them (the `propagate_symbols.py` imm64/TkID path
   already does this), and locate owners — thousands of era-correct anchors into
   data-driven game logic.
3. **Hunt round.** Feed the new anchors into the decompiler-in-the-loop pipeline
   (`ghidra_live.py dossier` + the match workflow) to reach the ~33 metadata-shaped
   unmapped functions and their neighbours. Cross-build port + adversarial verify as
   before; honest `unresolved` for the genuinely inlined.
4. **Priority targets:** the remaining Newton blockers and the interaction cluster
   (`GetInteractionData`/`FindFirstTypedComponent` in the older builds, marker cluster).

### C. Runtime struct fields (exe RE)

Newton reads runtime classes (`cGcPlanet`, `cGcSolarSystem`, `cGcApplication`,
`cGcPlayerEnvironment`, `cTkDynamicGravityControl`), whose `_vfields_` offsets are still
`{}`. Fill them from exe RE (1.09.1 named set first, diff forward), using MBIN where a
field is metadata-backed (e.g. `cGcPlanet::mPlanetGenerationInputData` ->
`GcPlanetGenerationInputData`, now a known MBIN struct). This is the classic per-field
verification loop, one field at a time.

### D. Newton bring-up

Wire the located offsets + verified structs and run NMS-Newton on each build, best-covered
first (1.38). Iterate on crashes and wrong reads; the framework's version gating already
lets Newton run unmodified (a missing hook/field degrades to None with a warning). Exit:
planets visibly move and saves survive on each build.

### E. RetroMBINCompiler (separate project)

Per `tools/mbin/RETRO_MBINCOMPILER.md`: one modern codebase carrying every retro build's
struct defs, selected at runtime by MBIN GUID; native `--dumplayout`; per-version types;
the 1.13 def set. Unblocks A.1 and A.4 cleanly and removes the per-tag patching.

## Milestones / exit criteria

- **M1 — Struct layer done.** 4-build layouts (incl. 1.13) ✅, per-build types ✅, globals
  generated + wired into `nmspy/globals.py` ✅, field offsets verified vs libMBIN ✅.
  Remaining: exe cross-check (A.2) and retiring `exported_types.py` after runtime classes
  (workstream C) and wider coverage.
- **M2 — MBIN-anchor hunt round.** GUID + TkID anchor tables built; a decompiler round
  closes the reachable metadata-shaped functions and the remaining Newton blockers.
- **M3 — Runtime fields.** Newton's runtime-class fields filled and exe-verified per build.
- **M4 — Newton on 1.38.** Boots, moves planets, saves survive.
- **M5 — Newton on all four builds.** Project complete for its stated goal.

## Sequencing

A, B, and C run in parallel (different surfaces). Newton (D) gates only on the specific
function + struct subset it uses, not the whole surface, so M4 can land well before full
coverage. E is the durable investment that makes A and future builds cheap; spin it up
when the per-tag patching becomes the bottleneck.
