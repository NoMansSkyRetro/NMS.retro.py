"""Locate filesystem_meta NOT_YET_FOUND functions across the four legacy builds.

Batch: cTkFileSystem / metadata / resource / XMLNode / async-IO functions.

Everything here is derived from stable, build-independent signals so the addresses
reproduce on a re-run (see tools/legacy_re/HUNTING.md). Reasoning is logged to
stderr; stdout is a single JSON object.

Signals used
------------
The legacy builds are FIOS2-based (Sony fios2). Each cTkFileSystem member is a thin
wrapper around exactly one sceFios* syscall; the same call is *inlined* into the many
metadata reflection/serialisation functions (cGc*::ClassPointerSave, ReadFromFile<T>,
WriteToXMLFile<T>), so a syscall LIKE-match returns hundreds of huge functions. The
real member is the unique *small* wrapper, isolated with a size ceiling. Verified by
decompilation in 1.38 (argument shapes + the syscall each ends in):

    Open(path,mode)        -> sceFiosFHOpenSync,        mode 0/1/2 -> FIOS flags, returns handle
    Write(buf,sz,cnt,h)    -> sceFiosFHWriteSync,       + cache InvalidatePath
    CreatePath(path)       -> sceFiosDirectoryExists/CreateSync
    DoesFileExist(path)    -> sceFiosExistsSync
    EnumerateDirectory     -> sceFiosDHOpenSync/DHReadSync (dir handle walk)

CreatePath and DoesFileExist have NO standalone wrapper in 1.13 / 1.09.1 (fully
inlined there -- the FS cluster in those builds contains only Read/Write/Enumerate
members); those slots are reported unresolved.

MiniDumpFunction is the unique function referencing the DbgHelp import
"MiniDumpWriteDump" (it writes "%s\\NMS_crash_%lld.dmp").

The remaining targets (mod-archive loaders, cTkMetaData*/XMLNode/cTkResource/
cTkAsyncIOManager/cTkEngineUtils) are reported unresolved: they are either inlined,
lack a modern signature to anchor against, or their engine/thread callees are not
symbolised in the Ghidra DBs, so no two independent signals could be established
without guessing.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import BUILDS, Binary  # noqa: E402

BUILDS_ORDER = ["1.38", "1.24", "1.13", "1.09.1"]


def log(*a):
    print(*a, file=sys.stderr)


def syscall_wrappers(b, syscall, max_size):
    """Functions whose decompilation calls `syscall` and are smaller than max_size.

    Direct DB query (not functions_matching, which caps by address order and would
    drop the high-address FS cluster behind the hundreds of inlined copies).
    """
    rows = b.db.execute(
        "SELECT address, size FROM decompilations "
        "WHERE raw_decomp LIKE ? AND size < ? ORDER BY size",
        (f"%{syscall}%", max_size),
    ).fetchall()
    return rows


def syscall_all(b, syscall):
    return b.db.execute(
        "SELECT address, size FROM decompilations WHERE raw_decomp LIKE ? ORDER BY size",
        (f"%{syscall}%",),
    ).fetchall()


def unique_wrapper(b, syscall, max_size, label):
    hits = syscall_wrappers(b, syscall, max_size)
    if len(hits) == 1:
        addr, size = hits[0]
        log(f"    {label}: 0x{addr:X} (size {size}) unique {syscall}<{max_size}")
        return addr
    log(f"    {label}: {len(hits)} candidates for {syscall}<{max_size}: "
        f"{[hex(a) for a, _ in hits]} -> unresolved")
    return None


def find_build(b):
    """Return (found: name->addr, notes: name->reason) for one build."""
    found = {}
    notes = {}
    log(f"  [{b.build}]")

    # --- cTkFileSystem thin syscall wrappers -------------------------------
    a = unique_wrapper(b, "sceFiosFHOpenSync", 400, "Open")
    if a:
        found["cTkFileSystem::Open"] = a
    else:
        notes["cTkFileSystem::Open"] = "no unique small sceFiosFHOpenSync wrapper"

    a = unique_wrapper(b, "sceFiosFHWriteSync", 170, "Write")
    if a:
        found["cTkFileSystem::Write"] = a
    else:
        notes["cTkFileSystem::Write"] = "no unique small sceFiosFHWriteSync wrapper"

    a = unique_wrapper(b, "sceFiosDirectoryCreateSync", 300, "CreatePath")
    if a:
        found["cTkFileSystem::CreatePath"] = a
    else:
        notes["cTkFileSystem::CreatePath"] = (
            "inlined in this build; no standalone sceFiosDirectoryCreateSync wrapper")

    a = unique_wrapper(b, "sceFiosExistsSync", 250, "DoesFileExist")
    if a:
        found["cTkFileSystem::DoesFileExist"] = a
    else:
        notes["cTkFileSystem::DoesFileExist"] = (
            "inlined in this build; no standalone sceFiosExistsSync wrapper")

    # EnumerateDirectory: of the exactly-two sceFiosDHOpenSync functions (the dir
    # enumerator and the MODS mod-archive loader), the enumerator is the smaller and
    # the one that does not reference the mod paths.
    dh = syscall_all(b, "sceFiosDHOpenSync")
    if len(dh) == 2:
        (a0, s0), (a1, s1) = dh  # ordered by size asc
        enum_addr = a0
        # sanity: the larger one is the mod loader (references MODS/.pak)
        mod_decomp = b.function_at(a1)[3]
        enum_decomp = b.function_at(a0)[3]
        if "MODS" in enum_decomp and "MODS" not in mod_decomp:
            enum_addr = a1  # unexpected ordering; pick the non-mod one
        log(f"    EnumerateDirectory: 0x{enum_addr:X} (size {min(s0, s1)}) "
            f"smaller of 2 sceFiosDHOpenSync funcs; other 0x{a1:X} is the MODS loader")
        found["cTkFileSystem::EnumerateDirectory"] = enum_addr
    else:
        notes["cTkFileSystem::EnumerateDirectory"] = (
            f"expected 2 sceFiosDHOpenSync funcs, found {len(dh)}")

    # --- MiniDumpFunction --------------------------------------------------
    md = syscall_all(b, "MiniDumpWriteDump")
    if len(md) == 1:
        addr = md[0][0]
        log(f"    MiniDumpFunction: 0x{addr:X} unique MiniDumpWriteDump ref")
        found["MiniDumpFunction"] = addr
    else:
        notes["MiniDumpFunction"] = f"expected 1 MiniDumpWriteDump ref, found {len(md)}"

    return found, notes


# Targets with no reliable two-signal anchor in these Ghidra DBs (inlined, no modern
# signature, or unsymbolised engine/thread callees). Reported unresolved rather than
# guessed, per HUNTING.md.
HARD_UNRESOLVED = {
    "cTkFileSystem::Data::MountAllArchives":
        "mod/archive mount orchestrator identifiable by role only (DISABLEMODS.TXT + "
        "psarc dearchiver); no modern signature to give a second signal",
    "cTkFileSystem::LoadModDirectory":
        "no modern signature/callees; only structural role (MODS/.pak enumeration)",
    "cTkFileSystem::LoadModSubdirectory":
        "no modern signature/callees; cannot separate from LoadModDirectory",
    "GenerateModdedFilepath":
        "no modern signature/strings/callees in hints; no anchor",
    "cTkFileSystem::IsModded":
        "17-byte bool accessor, inlined; no standalone function located",
    "XMLNode::writeToFile":
        "inlined into cTkMetaDataXML::WriteToXMLFile<T> (they carry the FHOpen/Write "
        "inline); no standalone function calls Open+Write+Close",
    "cTkMetaDataManager::GetInstance":
        "Meyers singleton pattern shared by many classes; kRegister dynamic-initializer "
        "callers not symbolised, no distinguishing second signal",
    "cTkMetaDataManager::LoadModdedData":
        "no modern signature/strings/callees; no anchor",
    "cTkMetaDataXML::GetLookup":
        "hash multiplier imm64 0x2E8BA2E8BA2E8BA3 is shared by 40+ funcs; callers "
        "(Register/Read/WriteClassPointer) not mapped -> no unique anchor",
    "cTkMetaDataXML::Register":
        "imm64 0x41110F412042100F migrated (owner in legacy is an unrelated struct-copy, "
        "verified); registrar callers not symbolised",
    "cTkResource::cTkResource":
        "base resource ctor; cEg*Resource ctor callers not mapped, no string anchor",
    "cTkEngineUtils::GetMasterModelNode":
        "Engine::GetModelNode/GetNodeParamI/GetNodeParent callees not symbolised; "
        "cluster candidates not distinguishable without guessing",
    "cTkEngineUtils::GetMatricesFromNode":
        "sole callee Engine::GetNodeTransMats not symbolised in the DBs",
    "cTkEngineUtils::RepositionGroupNode":
        "Engine::ShiftAllTransformsForNode/GetNodeFirstChild/NextSibling not symbolised",
    "cTkAsyncIOManager::GetOpData":
        "small critical-section accessor; TkThread::Lock/UnlockCriticalSection callees "
        "not symbolised, no string/imm anchor",
    "cTkAsyncIOManager::GetOpDataSize":
        "same as GetOpData; no independent signal to separate the two",
}


def main():
    per_name = {}
    unresolved = {}
    log("filesystem_meta finder")
    for build in BUILDS_ORDER:
        if build not in BUILDS:
            log(f"  [{build}] not configured, skipping")
            continue
        try:
            b = Binary(build)
        except Exception as e:  # missing exe/db
            log(f"  [{build}] SKIP ({e})")
            continue
        found, notes = find_build(b)
        for name, addr in found.items():
            # defensive: confirm it is a recorded function start
            if b.function_at(addr) is None:
                log(f"    !! {name} 0x{addr:X} not a function start, dropping")
                continue
            per_name.setdefault(name, {})[build] = f"0x{addr:X}"

    # Assemble unresolved reasons (one line each) for anything not fully found.
    for name, reason in HARD_UNRESOLVED.items():
        unresolved[name] = reason
    # Per-build inline gaps for the FS wrappers.
    for name in ("cTkFileSystem::CreatePath", "cTkFileSystem::DoesFileExist"):
        missing = [bd for bd in BUILDS_ORDER if bd not in per_name.get(name, {})]
        if missing:
            unresolved[name] = f"inlined (no standalone wrapper) in: {', '.join(missing)}"

    print(json.dumps({"functions": per_name, "unresolved": unresolved}))


if __name__ == "__main__":
    main()
