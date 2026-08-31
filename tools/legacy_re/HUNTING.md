# Finder hunt protocol

How to locate NOT_YET_FOUND functions across the four legacy builds and record the
result reproducibly. Read this fully before writing a finder.

## What you produce

For your assigned batch, one script: `tools/legacy_re/finders/find_<batch>.py`.
Running it (from `tools/legacy_re/`, `python finders/find_<batch>.py`) prints a single
JSON object to stdout and nothing else on stdout (log to stderr):

```json
{"functions": {"cGcX::Y": {"1.13": "0x1401234A0", "1.24": "0x140...", ...}},
 "unresolved": {"cGcX::Z": "one line: what was tried and why it failed"}}
```

Only include a build slot when you are confident. `merge_finder_results.py` re-runs
your script and validates every address against the decompilation DB, so a wrong
guess is caught, but do not pad with guesses: an honest `unresolved` entry is better.
Do NOT edit `nmspy/data/offsets.json` yourself; the merge tool owns it.

The script must be deterministic and self-contained (no network, no manual steps) so
anyone can reproduce your addresses by re-running it.

## Fast path: handles.py (use this first)

`handles.py` precomputes and caches (per build) the string-xref index, imm64 index,
and call graph, so you do not rebuild them. First construction builds the caches
(~1 min each, once per machine); after that `Xverse()` loads in seconds.

```python
from handles import Xverse
xv = Xverse()                          # all four builds, cached

xv.by_string("CRUISE: Max Boost")      # {build: [addrs]} referencing it (EXACT, trust it)
xv.by_string("PLANET", exact=False)    # substring search
xv.port("1.38", 0x1408F5620)           # {build: addr} same function everywhere (see below)
xv.port_candidates("1.38", 0x140...)   # {build: [(addr, score, why)]} ranked leads to verify
xv.callers("1.13", 0x140D4B460)        # exact
xv.callees("1.13", 0x140D4B460)        # exact
xv.neighbours("1.13", 0x140D4B460)     # address-adjacent funcs (same compilation unit)
xv.strings_of("1.13", 0x140D4B460)     # strings this function references
xv.name("1.38", 0x1408F5620)           # Ghidra name + size
xv.find_by_profiler_name("cGcGameState::LoadFromPersistentStorage")  # {build: [addrs]}
```

**Workflow that works:** locate a function in ONE build (usually 1.38, closest to the
4.13 PDB) by a distinctive string or profiler name, then `xv.port("1.38", va)` to get
the other three for free.

**Trusting the results:**
- `by_string`, `callers`, `callees`, `neighbours`, `strings_of`, `name` are EXACT
  (read straight from the indices) — trust them.
- `port` is high precision by design (it returns a build only when the string winner
  and call-graph winner agree, or one is overwhelming) but abstains on ~half of
  cases; **it is unreliable for generic library functions** (allocators, `GetInstance`,
  `Malloc`/`Free`, thin IO wrappers), so always decompile-verify a ported allocator/
  singleton before committing it.
- `port_candidates` never abstains; treat its output as leads to confirm, not answers.

Still verify each committed address with `xv.name(build, va)` (must be a real function,
not `None`) — the merge tool enforces this too.

## Tools available (all in tools/legacy_re/)

- `common.Binary(build)` — `.data` (exe bytes), `.db` (Ghidra SQLite, read-only),
  `.function_at(va)`, `.functions_matching(like, limit)`, `.va_to_file_offset(va)`,
  `.file_offset_to_va(off)`, `.read_ptr(va)`, `.sections`.
- `out/target_hints.json` — per target: modern signature, referenced `strings`,
  `imm64` constants, `modern_callees`/`modern_callers`, source file, length.
- `out/propagated_<build>.json` — 1,400-2,000 already-matched 4.13->legacy function
  pairs per build. If a target's modern callee/caller is in here, you can locate your
  target relative to it.
- `explore.py` (strings/grep/dump/range/vtable/dumpstr) for interactive checks.
- `propagate_symbols.py` internals (`load_side_413`, `Side`, `match_sides`) if you
  want to run a focused fingerprint/call-graph match programmatically.

## Method, in order of reliability

1. **Distinctive strings.** If a target references a string (see hints), find that
   string in the legacy exe, then the function referencing it. `explore.py strings
   <build> <text>` does both. A string referenced by exactly one function is a lock.
2. **imm64 TkID constants.** These FNV hashes are identical across versions. Scan the
   legacy `.text` for the same 8-byte immediate (see `imm64_refs` in
   propagate_symbols) and find the containing function.
3. **Anchored call graph.** If a `modern_callee`/`modern_caller` is already mapped
   (check offsets.json and propagated_<build>.json), the target sits at a known
   position relative to it: the unique caller of X, the function whose N-th call is X,
   a sibling in the same compilation unit (adjacent addresses).
4. **Cross-version transfer.** Once you locate a function in ONE build (usually 1.38,
   closest to modern), the other builds are months apart: find it there by the same
   strings, or by its position among already-matched neighbours. Locate once, port
   sideways. This is the "share signatures between versions" win; exploit it.
5. **Profiler name literal.** Some functions strncpy their own name; grep the legacy
   decomp for the `"cGcX::Y"` literal (harvest_name_literals already swept exact
   single-owner cases, but overloaded/multi-owner ones may still be resolvable by
   hand).
6. **Live-Ghidra dossier + decompiler (for the string-less remainder).** The functions
   left after the string/imm/name sweeps have no distinctive tokens, so the only handle
   is their call-graph position and their *behaviour*. `ghidra_live.py dossier <build>
   <out.json> <anchor_va>...` opens the analyzed project once and, per mapped anchor,
   dumps the anchor's decompiled body plus every callee (real ReferenceManager edges, so
   indirect/vtable calls the E8/E9 scan misses) with size, named grandchildren, and a
   decompiled body. Read the anchor's body to see the *context* of each call (what the
   result is used for), then match a callee to the target by: modern size band, own
   callee structure, and semantics from the decompiled body. `decompmany` decompiles an
   arbitrary VA list (e.g. an address-adjacent sibling cluster) in one JVM open. Confirm
   by cross-build size/shape consistency, then port sideways (method 4).

### The inlining ceiling (read before chasing a string-less target)

Many upstream functions are *not separately present* in the 2016-2017 builds: the older
MSVC inlined a small accessor into its one caller, `/OPT:ICF` folded it with an
identical sibling, or the modern refactor split a helper out of code that legacy kept
monolithic. A dossier makes this visible fast (the anchor's callee list simply has no
function of the target's shape). When that happens the target has no address to hook in
that build; report it `unresolved` with the reason (`inlined into <caller>`, `fused with
the Get<Type> family`, `folded with <sibling>`) rather than forcing a wrong match. That
honest reason is the deliverable: it moves the slot from "not yet tried" to "classified,
not hook-able here", which is as valuable as an address for the completeness goal.

## Rules

- Verify every address is a function START: `Binary(build).function_at(va)` must
  return a row. The merge tool enforces this; check it yourself first.
- Never overwrite an existing `0x...` in offsets.json. If your evidence disagrees with
  a curated address, put it in `unresolved` with the discrepancy, do not force it.
- Prefer few correct over many shaky. Two independent signals (string + call site,
  or same across two builds) before you commit a hard-to-verify one.
- Log reasoning to stderr so the derivation is auditable; keep stdout pure JSON.
