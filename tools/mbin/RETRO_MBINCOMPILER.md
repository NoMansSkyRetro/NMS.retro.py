# RetroMBINCompiler: design notes for a dedicated retro struct pipeline

This documents the approach NMS.retro.py uses to get authoritative per-build metadata
struct layouts, so it can be lifted into a proper standalone **RetroMBINCompiler** project
(the "retro" build monkeyman192 floated) instead of the per-tag patching we do here.

## The problem

`nmspy` needs the memory layout (field name, type, byte offset) of every mbin-backed
struct, per build, to read game memory. The modern `exported_types.py` is generated from
the 4.13 PDB and is wrong for the 1.x builds. libMBIN has the right definitions, but the
struct layouts changed across builds and the era tooling was incomplete.

## What we proved (the method to systematize)

libMBIN already computes each field's offset while it serializes a template. We tap that
directly, so we never reimplement its alignment rules:

1. **Get the era-matched libMBIN.** MBIN container format is `2500` for all four builds.
   Sources, pinned by the MBIN timestamp stamp (`tools/mbin/probe_versions.py`):

   | Build | Stamp | libMBIN source | How |
   |-------|-------|----------------|-----|
   | 1.09.1 | 2016-09-15 | `rc1` branch | modern engine, RC1/launch struct defs (has `OffsetOf`) |
   | 1.13   | 2016-10-21 | *none tagged* | predates MBINCompiler; needs the nearest commit or a retro branch |
   | 1.24   | 2017-03-23 | tag `1.24.4` | 2017 code, patched |
   | 1.38   | 2017-09-28 | tag `1.38.0.2` | 2017 code, patched |

   All build with the modern dotnet SDK: `dotnet build MBINCompiler/MBINCompiler.csproj -c
   Release` (the 2017 tags are net452; `rc1` is net6, run its output via
   `DOTNET_ROLL_FORWARD=Major dotnet MBINCompiler.dll`).

2. **Capture offsets from the build's own serializer.** `NMSTemplate.AppendToWriter` walks
   fields and already computes `fieldAddr = writer.Position - templatePosition`. Add:
   - a static `CaptureOffsets` flag, a `CaptureDepth` counter, and a `CapturedFields` list;
   - in the field loop, `if (CaptureOffsets && CaptureDepth == 1) CapturedFields.Add(name,
     fieldAddr, fieldType)` — the **depth guard is essential**: a nested struct whose first
     field sits at offset 0 also has `templatePosition == 0`, so filter by recursion depth,
     not position;
   - a `--dumplayout` command that, per `NMSTemplate` subclass, resets capture, calls
     `GetDataSize()` (which triggers the serialize walk), and emits
     `{struct: {size, fields:[{name, type, offset, size}]}}` (field size = next offset − this
     offset).

   The exact edits are saved as `patches/dumplayout-1.24.4.patch` and
   `patches/dumplayout-1.38.0.2.patch`. For the modern `rc1` engine we instead use its
   public `NMSTemplate.OffsetOf`/`SizeOf` directly (see `structdump/`), no patch needed.

3. **Merge into `nmspy`.** `gen_structs.py` merges the per-build layout JSON by field name
   into `versioned_struct` classes: an offset identical across builds collapses to one int,
   a moved field or rename is expressed per version. libMBIN's type maps to a real ctype for
   primitives/vectors and a correctly-sized opaque blob otherwise.

Result so far: 1.09.1 (525 templates), 1.24 (704), 1.38 (890) dumped in
`tools/mbin/layouts/`; the Newton-relevant globals generate as multi-version structs.

## What a dedicated RetroMBINCompiler should do better

The above works but is per-tag surgery. A proper project would:

1. **One codebase, per-version struct definitions.** Like `rc1` but carrying the struct
   sets for *every* retro build (1.09.1/1.13/1.24/1.38), selected at runtime. That removes
   the "build each old tag" step and lets a single modern binary dump any build.
2. **Version detection by GUID.** Each MBIN header carries the template GUID
   (`tools/mbin/mbin.py` reads it). Pick the matching definition set by GUID instead of by
   which binary you built. Where a struct's GUID is stable across builds, one definition
   serves several.
3. **Ship `--dumplayout` natively** (upstream it), emitting per-version layout JSON as a
   first-class output alongside MBIN↔EXML.
4. **Model per-version field *types*, not just offsets.** Heavily restructured structs (e.g.
   `GcEnvironmentGlobals`, 0x330 in 1.09.1 vs 0x460 in 1.38) have the same field name at the
   same offset with a *different type* per build; our name-merge keeps one ctype and only
   the offsets diverge. The retro tool should emit type-per-version so codegen is exact for
   volatile structs (nmspy's `versioned_struct` would need a per-version ctype to consume it).
5. **Fill the 1.13 gap.** No MBINCompiler existed at Foundation; either bisect to the
   nearest commit whose GUIDs match 1.13's MBINs, or hand-author a 1.13 definition set in the
   retro codebase.
6. **Advance the `Unknown<offset>` frontier.** ~50% of early-build fields are still
   `Unknown<offset>` (correctly placed, unnamed). Naming them is ordinary upstream RE and
   flows straight through this pipeline once done.

## Open items to close before trusting the output

- **Verify offsets against the exe** for a few structs per build (the layouts are internally
  consistent, but confirm libMBIN's serialized layout equals the in-memory C++ layout, which
  is the assumption that lets us hook them).
- **Nested structs and lists** are opaque blobs today; emit them as real nested
  `versioned_struct` references once the generator does dependency ordering.
