# Legacy RE tooling

Every address in `nmspy/data/offsets.json` was derived with the scripts in this folder,
so the process is transparent and repeatable. Nothing in the data file is hand-waved:
each entry can be re-verified against the decompilation databases.

## Inputs (not in this repo)

- The four Steam-era binaries:
  `E:\NMSLegacy\no_mans_sky_v<ver>\Binaries\NMS.exe` for 1.09.1, 1.13, 1.24, 1.38.
- Per-build Ghidra decompilation databases (SQLite, one row per function with its
  decompiled C) produced by `E:\NMSLegacy_Decomp\build_all_ghidra.py`:
  - `E:\NMSLegacy_Decomp\NMS1091_GHIDRA_ANALYSIS\decomp.db`
  - `E:\NMSLegacy_Decomp\NMS113_GHIDRA_ANALYSIS\decomp.db`
  - `E:\NMSLegacy_Decomp\NMS124_GHIDRA_ANALYSIS\decomp.db`
  - `E:\NMSLegacy_Decomp\NMS138_GHIDRA_ANALYSIS\decomp.db`

Paths live in `common.py`; edit them there if your layout differs.

**Provenance caveat:** always run `verify_alignment.py` before trusting a database.
The original 1.09.1 analysis turned out to be built from the GOG binary (PE timestamp
`0x57FF732B`), not the Steam one (`0x57FF70CA`); the two were linked ten minutes apart
and their code layouts differ, so addresses do not transfer. The Steam 1.09.1
database was rebuilt from scratch.

## Scripts

- `common.py` — shared plumbing: build registry, PE section parsing,
  virtual-address ↔ file-offset conversion, decomp DB access.
- `explore.py` — the interactive workhorse used to identify functions. Subcommands:
  - `strings <build> <needle>` — find a NUL-terminated string in the exe, report its
    virtual address and every decompiled function referencing it.
  - `grep <build> <pattern>` — list functions whose decompiled C contains a substring.
  - `dump <build> <address>` — print a function's decompiled C.
  - `range <build> <start> <end>` — list functions in an address range (compilation
    units cluster, so neighbours of a known function are often related).
  - `vtable <build> <address> [n]` — read n pointer slots at a data address and name
    the functions they point to.
- `find_boot_set.py` — automates the boot-set identification chain (FSM cluster,
  application globals, main loop) for one build and merges into offsets.json.
- `harvest_name_literals.py` — maps profiler string literals (functions that
  `strncpy` their own name) to their containing functions; ~24 exact symbols per
  build.
- `propagate_symbols.py` — the mass mapper: matches upstream NMS.py's 4.13 hook
  surface (`upstream_data_413.json`, from upstream git history) to legacy functions
  by fingerprinting distinctive string references and TkID imm64 constants on both
  sides. Requires the 4.13 exe + PDB dump (paths at the top of the script).
- `try_modern_signatures.py` — evaluates upstream's modern byte signatures against a
  legacy exe. Verdict: ~4% "unique" hits, and cross-checking against known ground
  truth shows even those are mostly false positives (e.g. it places cTkFSM::Update
  at the wrong address). Kept as documentation of why we don't signature-match.
- `verify_alignment.py` — proves a decomp DB and an exe are the same binary (padding
  bytes before every recorded function start). Run this before trusting any database.
- `verify_offsets.py` — cross-checks every address in `nmspy/data/offsets.json`
  against the decomp DBs (the address must be a known function start in that build).

## Methodology

Identification works backwards from distinctive artifacts:

1. **Strings.** Debug/log format strings, mbin paths, and FSM state IDs survive in
   `.rdata`. `explore.py strings` maps a string to its referencing functions.
2. **Known neighbours.** MSVC keeps compilation-unit functions contiguous, so once one
   function of a class is identified, `explore.py range` around it usually reveals the
   rest of the class.
3. **Vtables.** Static objects reveal their vtable pointer in their constructor;
   `explore.py vtable` then names the virtual functions.
4. **Cross-version propagation.** A function identified in one build is located in the
   others by its strings and call-graph shape (see `propagate_symbols.py`, Phase 2).

Findings worth keeping are recorded in `findings.md` alongside the offsets they
produced.
