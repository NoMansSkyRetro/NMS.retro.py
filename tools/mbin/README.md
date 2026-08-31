# MBIN tooling: metadata structs from the shipped archives

NMS stores its game metadata (globals, biomes, atmospheres, recipes, entity templates)
as compiled `.MBIN` files inside PSARC `.pak` archives. `nmspy/data/exported_types.py`
is generated from the modern 4.13 PDB, so its layouts are wrong for the 1.x builds; the
plan (PLAN.md §4) was to regenerate the **mbin-backed** structs from the definitions that
match each build's era.

**Status: done for the globals layer.** The authoritative per-build layouts now come from
[MBINCompiler.retro](https://github.com/NoMansSkyRetro/MBINCompiler.retro) (a fork of
monkeyman192's rc1 branch carrying a byte-perfect struct set per build), dumped with its
`dumplayout` command into `layouts/`, merged into per-build `versioned_struct` classes by
`gen_structs.py`, and wired into `nmspy/globals.py` via the generated
`nmspy/data/mbin_globals.py`. `tools/mbin/test_layouts.py` checks every generated field
against libMBIN's own offset in all four builds. The tools below read the archives/headers
directly and pin each build to its libMBIN era; that pinning is what MBINCompiler.retro is
built on.

Idea credit: monkeyman192 (NMS.py author) suggested python-ifying the era-matched
MBINCompiler struct definitions rather than trusting the modern PDB.

## Tools

- **`psarc.py`** — minimal read-only PSARC v1.4 reader. `Psarc(path).names` lists the
  stored files; `.read(name)` returns decompressed bytes. CLI: `python psarc.py <pak>`
  lists the MBINs in an archive.
- **`mbin.py`** — MBIN header reader (`read_header(bytes) -> MbinHeader`). The header
  gives the format version, the **timestamp stamp** libMBIN keys on (decimal
  `YYYYMMDDHHMM`), the root template **GUID**, and the template class name.
- **`probe_versions.py`** — reports each legacy build's MBIN stamp + GUID and the
  matching libMBIN tag. This is how each build is pinned to a point in libMBIN history.
- **`decompile.py`** — extracts metadata MBINs from a build's PAKs and decompiles them to
  EXML with the era-matched MBINCompiler. `python decompile.py 1.24 [name-filter]` writes
  `out/exml/1_24/*.exml`.
- **`analyze_structs.py`** — diffs a struct's fields across builds from the EXML.
  `python analyze_structs.py GCENVIRONMENTGLOBALS.GLOBAL` shows added/removed/changed
  fields per version, the raw material for a `versioned_struct`.
- **`structdump/`** — a small C# tool that references the rc1 `MBINCompiler.dll` and dumps
  every `NMSTemplate`'s authoritative layout (name, type, offset, size) using libMBIN's own
  `OffsetOf`/`SizeOf`, so we never reimplement its alignment logic. Writes
  `out/rc1_layout.json` (525 structs).
- **`gen_structs.py`** — turns that layout JSON into nmspy `versioned_struct` classes:
  primitives/vectors map to real ctypes, everything else becomes a correctly-sized opaque
  blob tagged with its real type. `python gen_structs.py Globals` prints a module.
- **`test_mbin.py`** — self-check: round-trips a globals MBIN out of the 1.38 install.

## The authoritative layout path (MBINCompiler.retro)

monkeyman192 pointed us at the **`rc1` branch** of MBINCompiler: the RC1/launch struct
definitions reverse-engineered with modern methodology. That became
[MBINCompiler.retro](https://github.com/NoMansSkyRetro/MBINCompiler.retro), one binary that
carries a byte-perfect struct set per targeted build (rc1/1.09.1/1.13/1.24/1.38) in its own
namespace folder over a shared base, selected at runtime. Its `dumplayout` command emits the
**effective** per-build layout (the build's folder overlaid on the shared base, exactly as
the runtime resolves types), which is the clean per-version input this pipeline needs:

```
# in the MBINCompiler.retro checkout (net6; only net9 runtime here, so run via roll-forward):
DOTNET_ROLL_FORWARD=LatestMajor dotnet Build/Release/win-x64/MBINCompiler.retro.dll \
    dumplayout --nms-version=1.13 > tools/mbin/layouts/layout_1.13.json
# then, in this repo:
python tools/mbin/gen_structs.py globals-module > nmspy/data/mbin_globals.py
python tools/mbin/test_layouts.py     # verify every field vs libMBIN's offset
```

`GcEnvironmentGlobals` comes out at 0x330 (1.09.1) → 0x360 (1.13) → 0x450 (1.24) → 0x460
(1.38) with exact types and offsets that match the `Unknown<offset>` field names, confirming
the engine is authoritative. Where a field is still `Unknown<offset>` that is the genuine RE
frontier, not a tooling gap.

The older per-tag path (`structdump/` against the rc1 DLL, and the `patches/dumplayout-*.patch`
edits to the 1.24.4 / 1.38.0.2 tags) is how these layouts were first produced and is kept for
reference; MBINCompiler.retro supersedes it with one binary that dumps any build, including
the **1.13** layout that no released MBINCompiler tag could reach.

## MBINCompiler binaries (not in the repo)

`decompile.py` shells out to `MBINCompiler.<ver>.exe` in `tools/mbin/bin/` (gitignored).
Get them from the NoMansSkyRetro bundle (`MBINCompiler1to1.38.zip`) or MBINCompiler's
GitHub releases/tags. Verified-good, era-matched:
`1.09.1 -> 1.09.1`, `1.13 -> 1.13.2`, `1.24 -> 1.24.4`. **1.38 is missing a usable binary**
(the bundle's 1.31/1.34/1.38 copies are corrupt HTML and no GitHub release ships a built
exe), so build `1.38.0.2` from its tag, or decompile 1.38's stable structs with 1.24.4
where the GUID matches.

## Two findings that shape the struct codegen

- **Offsets come free from the era EXML.** The 2016-era compiler names fields it had not
  yet reverse-engineered `Unknown<hexoffset>` (`Unknown0`, `Unknown10`, `Unknown1C`, ...),
  which *is* the byte offset. So even where names are missing, the layout is recoverable.
- **Names improved over versions.** `GcEnvironmentGlobals` is 35 mostly-`Unknown*` fields
  in 1.09.1/1.13 but 124 properly-named fields in 1.24. So take **offsets from the
  era-matched compiler** (correct per build) and **names from the newest compiler that
  still knows the struct's GUID**, then reconcile.

## What the probe established

```
build     format  stamp             guid                libMBIN tag
1.09.1     2500  2016-09-15 10:09  0x7874BDDACA5369F2  (pre-release)
1.13       2500  2016-10-21 09:32  0x921F6EE7A2F8E1F4  (pre-release)
1.24       2500  2017-03-23 12:21  0xD3678373BD2A38F3  1.24.4
1.38       2500  2017-09-28 20:00  0x7DB5F3DF6DFEC088  1.38.0.2
```

- The MBIN **container format is 2500 for all four builds**, so one reader covers them.
- MBINCompiler's tagged history starts at **1.24.3**, so **1.24 → tag 1.24.4** and
  **1.38 → tag 1.38.0.2** are exact-era matches; their struct definitions decompile
  those builds' MBINs directly.
- **1.09.1 and 1.13 predate any MBINCompiler release.** The resolution is per-struct:
  compare each template's GUID against the 1.24 build's. Where the GUID matches, the
  1.24.4 definition applies unchanged; where it differs (as `cGcEnvironmentGlobals` does
  in every build here) the layout evolved and that struct must be reversed from the exe
  or hand-ported from the nearest libMBIN commit.

## Per-build layouts (all four builds)

Effective per-build layouts are dumped from MBINCompiler.retro and committed under `layouts/`
(regenerable): `layout_1.09.1.json` (535), `layout_1.13.json` (651), `layout_1.24.json` (714),
`layout_1.38.json` (905 templates). `gen_structs.py globals-module` merges them by field name
into per-version `versioned_struct` classes with **per-build types** (a field whose layout
changed across builds reads each build correctly), and `test_layouts.py` checks every field
against libMBIN's offset. **1.13 — the build no released MBINCompiler tag could reach — is now
covered** by MBINCompiler.retro's re-derived `V1_13` set.

The full approach, and how it was folded into the standalone MBINCompiler.retro, is written up
in [RETRO_MBINCOMPILER.md](RETRO_MBINCOMPILER.md).

## Remaining

1. **Runtime C++ classes** (`nmspy/data/types.py`: `cGcApplication`, `cGcPlanet`,
   `cGcSolarSystem`, the managers/HUD, `cTkDynamicGravityControl`) are **not** mbin-backed, so
   `dumplayout` does not cover them; their `_vfields_` still need exe RE (PLAN2 workstream C).
2. **Nested drill-down.** Nested struct / list fields are correctly-sized opaque blobs today;
   emit them as real nested `versioned_struct` references once the generator does dependency
   ordering.
3. **Exe cross-check.** Field offsets match libMBIN's serialized layout; spot-verify a few
   against the running exe to confirm the serialized layout equals the in-memory layout for
   the container-bearing structs (flat globals already agree by construction).
4. **Widen coverage** beyond the ~38 mapped globals: `gen_structs.py <Name>` already emits any
   template, so retire more of `exported_types.py` as mods need those structs per build.
