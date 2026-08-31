# MBIN tooling: metadata structs from the shipped archives

NMS stores its game metadata (globals, biomes, atmospheres, recipes, entity templates)
as compiled `.MBIN` files inside PSARC `.pak` archives. `nmspy/data/exported_types.py`
is generated from the modern 4.13 PDB, so its layouts are wrong for the 1.x builds; the
plan (PLAN.md §4) is to regenerate the **mbin-backed** structs from the definitions that
match each build's era. This directory reads the archives and headers directly so that
regeneration has clean, per-version inputs, no external tool required.

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
- **`test_mbin.py`** — self-check: round-trips a globals MBIN out of the 1.38 install.

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

## Next step (struct codegen)

The decompile pipeline is proven (extract -> EXML with field names) for 1.09.1/1.13/1.24.
Remaining to turn EXML into `nmspy` structs:

1. Get exact **types** (EXML gives name + order + a coarse kind, not `float` vs `int32`
   vs fixed-array-size). Either infer from the era compiler's `Unknown<offset>` gaps
   (successive offsets give each field's size) or read the MBINCompiler assembly's
   `NMSTemplate` field types via reflection-only metadata (no code execution).
2. Emit per-version `versioned_struct` classes (offsets from the era EXML, names from the
   newest compiler that knows the GUID), adapting `tools/create.py`.
3. Verify a handful of offsets against the exe before trusting the rest.
4. Get a usable **1.38** MBINCompiler (build `1.38.0.2`).

Start with the Newton-relevant set (planet/biome/atmosphere/environment globals).
