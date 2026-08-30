# NMS.retro.py

NMS.retro.py is a fork of [monkeyman192's NMS.py](https://github.com/monkeyman192/NMS.py)
that targets four **legacy** No Man's Sky builds instead of the modern game:

| Version | Update | Steam build |
|---------|--------|-------------|
| 1.09.1  | Release (final patch) | 2016-10-13 |
| 1.13    | Foundation | 2016-12-08 |
| 1.24    | Path Finder | 2017-03-23 |
| 1.38    | Atlas Rises | 2017-09-29 |

The running build is detected automatically from the exe's PE header timestamp, and
game functions are located by per-build static addresses (`nmspy/data/offsets.json`)
rather than byte-pattern scanning; these builds are frozen forever, so their addresses
are too. Every address is derived reproducibly with the scripts in `tools/legacy_re/`,
which document the whole reverse-engineering process.

See [PLAN.md](PLAN.md) for the retargeting design and current phase.

## How the addresses were found

The hard problem in retargeting is relocating ~330 functions (the surface upstream
NMS.py hooks) into four binaries that predate the 4.13 PDB by six years. Modern byte
signatures do not survive that gap (measured: ~4% match, mostly false positives), so
this fork maps functions **structurally** and records every result in
`nmspy/data/offsets.json`, where each slot is an address, `NOT_YET_FOUND`, or
`NOT_IN_THIS_VERSION` (with a note on the release history).

Coverage of the upstream hook surface so far: **1.09.1: 112, 1.13: 120, 1.24: 124,
1.38: 130** of ~330 functions, plus the struct-field and version-detection layers.
The remaining slots are dominated by functions that are inlined, ICF-folded, or belong
to features that postdate these 2016-2018 builds; `tools/legacy_re/findings.md` records
which and why.

### The tooling (`tools/legacy_re/`)

- **`handles.py`** — the cross-version toolkit. Caches per-build string-xref, TkID
  immediate, and call-graph indices, then exposes `Xverse().by_string()`,
  `.port()` (locate a function in one build, get its address in all four),
  `.port_candidates()`, `.callers()/.callees()/.neighbours()`, and
  `.find_by_profiler_name()`. This is the fast path for any new hunt.
- **`propagate_symbols.py`** — bulk matcher. Fingerprints distinctive string
  references and TkID constants, then expands matches through the call graph, chaining
  4.13 -> 1.38 -> 1.24 -> 1.13 -> 1.09.1 (the hard six-year hop is crossed once, then
  months-apart builds cascade).
- **`find_boot_set.py`, `harvest_name_literals.py`** — automated seeds (the
  application FSM cluster; functions that embed their own name as a profiler literal).
- **`build_full_surface.py`, `generate_hook_stubs.py`** — regenerate the flagged
  surface in `offsets.json` and the gated hook stubs in `nmspy/data/generated_hooks.py`.
- **`merge_finder_results.py`** — validates and merges hunt results, re-checking every
  address is a real function start before it lands.
- **`verify_offsets.py`, `verify_alignment.py`** — invariant checks (every address is a
  function start; a decomp database actually matches its exe).
- **`HUNTING.md`, `findings.md`** — the hunt protocol and the running derivation log.

### The agent-fleet approach

Beyond the deterministic tooling, large sweeps of the "not yet found" surface were run
as **fleets of Claude agents**: a Claude Fable orchestrator partitions the unmapped
functions into batches and dispatches one Claude Opus agent per batch. Each agent works
its batch with the shared toolkit and the RE protocol in `HUNTING.md`, then emits a
small script under `tools/legacy_re/finders/` whose output the orchestrator validates
and merges centrally, so no agent writes an address that is not first confirmed to be a
real function start. Agents report honest `unresolved` reasons instead of guessing, and
cross-version transfer (find once in the build closest to the PDB, port sideways) does
the heavy lifting. Two such rounds mapped ~210 addresses across the four builds.

**NOTE:** Any responsibility for broken saves is entirely on the users of this library.
This library will never contain functions relating to online functionality.

## Installation

Install from a clone of this repository (the `nmspy` package on PyPI is the modern
upstream, not this fork):

```
python -m pip install -e .
```

This installs NMS.py's dependency [`pyMHF`](https://github.com/monkeyman192/pyMHF)
as well.

## Usage

```
pymhf run nmspy
```

When configuring pyMHF, point it at a legacy install's `NMS.exe` (there is no Steam
app id to launch through; Steam only serves the modern build). If NMS.py starts up
successfully you should see two extra windows; an auto-created GUI from pyMHF, and a
terminal window which will show the logs for pyMHF.

## Writing mods

See the [pyMHF docs](https://monkeyman192.github.io/pyMHF/) for the framework
basics. Hook coverage differs per build: a hook whose address is not yet mapped for
the running build is disabled with a warning, and `nmspy.versions.CURRENT_VERSION`
tells you which build you are on.

## Contributing

The most valuable contribution is mapping more functions and struct fields. Read
`tools/legacy_re/README.md` for the methodology and `HUNTING.md` for the hunt
protocol; start from `handles.py` (`Xverse().by_string(...)` / `.port(...)`). New
addresses go into `nmspy/data/offsets.json` with a note in
`tools/legacy_re/findings.md`, and `tools/legacy_re/verify_offsets.py` must pass. The
highest-leverage manual targets are anchors that unlock a whole cluster once found
(e.g. `cGcMarkerPoint::IsEqual` for the marker/HUD functions).

## Credits

NMS.py is by [monkeyman192](https://github.com/monkeyman192), built on minhook,
cyminhook and pymem, with contributions and RE help from vitalised, gurren3, RaYRoD
and many others; see the upstream repository for the full credits. The retro
retargeting is by the [NoMansSkyRetro](https://github.com/NoMansSkyRetro) organization.
