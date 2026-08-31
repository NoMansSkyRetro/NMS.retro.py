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
- **`test_mbin.py`** — self-check: round-trips a globals MBIN out of the 1.38 install.

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

## Next step (struct regeneration)

For 1.24 and 1.38: check out MBINCompiler at the matching tag, decompile the relevant
globals/metadata MBINs to EXML (field names + types + order), and emit per-version
struct modules for `nmspy` (adapting `tools/create.py`). Field order in a template is
field order in memory, so this yields offsets to verify against the exe. For 1.13/1.09.1:
run the GUID diff first, reuse the stable structs, and reverse only the changed ones.
Start with the Newton-relevant set (planet/biome/atmosphere/environment globals).
