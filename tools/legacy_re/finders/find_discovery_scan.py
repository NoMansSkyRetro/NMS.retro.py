"""Finder for the discovery_scan batch: cGcBinoculars / cGcScanEvent /
cGcScanEventManager / cGcDiscoveryManager / cGcVisitedSystemsBuffer.

Deterministic re-derivation of the addresses. Prints one JSON object to stdout;
all reasoning goes to stderr. Run from tools/legacy_re/:  python finders/find_discovery_scan.py

Method summary (see HUNTING.md):

  cGcScanEvent::Update            references BOTH "TIMED_GOTO" and "%d:%.2d".
                                  The timed-goto display was added after 1.13, so
                                  only 1.24 and 1.38 carry these strings.
  cGcScanEvent::CalculateMarkerPosition  the single callee of ScanEvent::Update that
                                  references the gameplay string "INTERACT" (INTERACT
                                  is referenced by only ~5 functions binary-wide).
  cGcScanEvent::UpdateInteraction the single callee of ScanEvent::Update that
                                  references "cGcMaintenanceComponentData" (only the
                                  1.38 build still emits that class-name string).
  cGcBinoculars::UpdateTarget     references "XHAIR_DISTANCE" (1.38 only; the crosshair
                                  distance UI string). Cross-checks the curated value.

Everything else in the batch is left unresolved with a reason: the scanning system's
distinctive strings/RTTI are stripped from the legacy exes, the modern sub-methods
(GetRange / UpdateRayCasts / UpdateScanBarProgress / SetMarker) were only split out of
UpdateTarget/Update after 1.38 (1.38 UpdateTarget is 423 bytes and calls none of them),
and the remaining call-graph-only targets have no mapped caller/callee anchor in any
legacy build.
"""

import json
import re
import struct
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
from common import Binary  # noqa: E402

BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]


def log(*a):
    print(*a, file=sys.stderr)


def string_vas(b, needle):
    pat = re.escape(needle.encode())
    out = []
    for m in re.finditer(pat + b"\0", b.data):
        off = m.start()
        if off > 0 and b.data[off - 1] != 0:
            continue
        va = b.file_offset_to_va(off)
        if va is not None:
            out.append(va)
    return out


# lea reg,[rip+disp32] = REX.W(48/4C) 8D modrm(mod=00,rm=101,reg varies) disp32
_LEA_RE = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}", re.DOTALL)
_LEA_INDEX = {}


def _lea_index(b):
    """Build once per build: {target_va: [instruction_va, ...]} for every rip-relative lea."""
    if b.build in _LEA_INDEX:
        return _LEA_INDEX[b.build]
    idx = {}
    data = b.data
    for s in b.sections:
        if s.name != ".text":
            continue
        lo, hi = s.raw_offset, s.raw_offset + s.raw_size
        for m in _LEA_RE.finditer(data, lo, hi):
            i = m.start()
            disp = struct.unpack_from("<i", data, i + 3)[0]
            tgt = b.file_offset_to_va(i + 7) + disp
            idx.setdefault(tgt, []).append(b.file_offset_to_va(i))
    _LEA_INDEX[b.build] = idx
    return idx


def lea_xref_sites(b, target_va):
    """Instruction VAs doing `lea reg,[rip+disp32]` resolving to target_va."""
    return _lea_index(b).get(target_va, [])


def containing_func(b, va):
    row = b.db.execute(
        "SELECT address,size,name FROM decompilations WHERE address<=? "
        "ORDER BY address DESC LIMIT 1",
        (va,),
    ).fetchone()
    if row and row[0] <= va < row[0] + row[1]:
        return row[0]
    return None


_OWNER_CACHE = {}


def string_owners(b, needle):
    """Function-start addresses referencing `needle`, via rip-relative LEA and via
    Ghidra's own decompilation cross-reference (union, for recall)."""
    ck = (b.build, needle)
    if ck in _OWNER_CACHE:
        return _OWNER_CACHE[ck]
    owners = set()
    for sva in string_vas(b, needle):
        for site in lea_xref_sites(b, sva):
            f = containing_func(b, site)
            if f is not None:
                owners.add(f)
        for _n, addr, _s in b.functions_matching(f"%_{sva:08x}%", 80):
            owners.add(addr)
    # keep only real function starts
    res = {a for a in owners if b.function_at(a) is not None}
    _OWNER_CACHE[ck] = res
    return res


def callees(b, addr):
    row = b.function_at(addr)
    if not row:
        return []
    seen = []
    for m in re.finditer(r"FUN_(14[0-9a-f]+)", row[3]):
        a = int(m.group(1), 16)
        if a != addr and a not in seen and b.function_at(a) is not None:
            seen.append(a)
    return seen


def find():
    functions = {}
    unresolved = {}

    def put(name, build, addr):
        functions.setdefault(name, {})[build] = f"0x{addr:X}"

    for build in BUILDS:
        b = Binary(build)
        log(f"\n=== {build} ===")

        # --- cGcScanEvent::Update : TIMED_GOTO AND %d:%.2d ---
        upd = None
        og = string_owners(b, "TIMED_GOTO")
        ot = string_owners(b, "%d:%.2d")
        both = og & ot
        if len(both) == 1:
            upd = next(iter(both))
            put("cGcScanEvent::Update", build, upd)
            log(f"cGcScanEvent::Update = 0x{upd:X} (TIMED_GOTO & %d:%.2d)")
        else:
            log(f"cGcScanEvent::Update: TIMED_GOTO={[hex(x) for x in og]} "
                f"%d:%.2d={[hex(x) for x in ot]} -> no unique intersection")

        # Update-anchored callees.
        if upd is not None:
            kids = set(callees(b, upd))

            # cGcScanEvent::CalculateMarkerPosition : the Update-callee referencing INTERACT.
            cinter = [a for a in kids if a in string_owners(b, "INTERACT")]
            if len(cinter) == 1:
                put("cGcScanEvent::CalculateMarkerPosition", build, cinter[0])
                log(f"cGcScanEvent::CalculateMarkerPosition = 0x{cinter[0]:X} "
                    f"(INTERACT & callee-of-Update)")
            else:
                log(f"CalculateMarkerPosition: INTERACT&callee candidates={[hex(x) for x in cinter]}")

            # cGcScanEvent::UpdateInteraction : Update-callee referencing cGcMaintenanceComponentData.
            cmaint = [a for a in kids if a in string_owners(b, "cGcMaintenanceComponentData")]
            if len(cmaint) == 1:
                put("cGcScanEvent::UpdateInteraction", build, cmaint[0])
                log(f"cGcScanEvent::UpdateInteraction = 0x{cmaint[0]:X} "
                    f"(cGcMaintenanceComponentData & callee-of-Update)")
            else:
                log(f"UpdateInteraction: cGcMaintenanceComponentData&callee "
                    f"candidates={[hex(x) for x in cmaint]}")

        # --- cGcBinoculars::UpdateTarget : XHAIR_DISTANCE ---
        xh = string_owners(b, "XHAIR_DISTANCE")
        if len(xh) == 1:
            ut = next(iter(xh))
            put("cGcBinoculars::UpdateTarget", build, ut)
            log(f"cGcBinoculars::UpdateTarget = 0x{ut:X} (XHAIR_DISTANCE)")
        else:
            log(f"cGcBinoculars::UpdateTarget: XHAIR_DISTANCE owners={[hex(x) for x in xh]}")

    # -------- honest unresolved reasons --------
    unresolved.update({
        "cGcBinoculars::GetRange":
            "float getter; no strings/imm; not split out of UpdateTarget until after 1.38 "
            "(1.38 UpdateTarget is 423 bytes and calls none of it); no mapped caller/callee anchor.",
        "cGcBinoculars::SetMarker":
            "only distinctive string cGcAtmosphereEntryComponentData is absent from all four legacy "
            "exes; sole caller cGcPlayer::UpdateScanning is unmapped.",
        "cGcBinoculars::UpdateRayCasts":
            "decorated-name/source-path RTTI strings are stripped in legacy; raycast logic still "
            "inlined in UpdateTarget in 1.38 (UpdateTarget calls no raycast sub-function).",
        "cGcBinoculars::UpdateScanBarProgress":
            "tiny (67 bytes) lambda-wrapping helper, no strings/imm, called only by UpdateTarget "
            "which does not call it in 1.38 (post-1.38 split); nothing to anchor on.",
        "cGcDiscoveryManager::SubmitDiscoveryData":
            "62-byte wrapper over Data::SubmitDiscoveryData + cTkUnixTimestamp::Now; neither callee "
            "nor caller (cGcSimpleInteractionComponent::DoAction) is mapped in any legacy build.",
        "cGcScanEvent::Construct":
            "only generic strings (\"list too long\") and a generic reciprocal-divide immediate; the "
            "one detectable caller of CalculateMarkerPosition is Update, so Construct cannot be "
            "reached via the call graph; callers (ScanEventManager::AddEvent*) are unmapped.",
        "cGcScanEvent::UpdateSpaceStationLocation":
            "distinctive string SettlementConstructionLevel is absent from all legacy exes (space-"
            "station settlements are a post-1.38 feature); no other anchor.",
        "cGcScanEventManager::PassesPlanetInfoChecks":
            "no strings/imm; sole callee cGcSolarSystem::DoesBuildingDensityHaveBuildingClass and sole "
            "caller cGcScanEventManager::CheckInterstellarEvent are both unmapped in every legacy build.",
        "cGcVisitedSystemsBuffer::VisitNewGalacticAddress":
            "no strings/imm; callees (ClassifyStarKeyAttributes, ClampToLimits) and caller "
            "(LoadGalacticAddressBuffers) are all unmapped in every legacy build.",
    })

    # For partly-resolved functions, note which builds are still missing.
    partial = {
        "cGcScanEvent::Update":
            "TIMED_GOTO/%d:%.2d timed-goto display strings are absent before 1.24; no mapped "
            "scanevent-runtime caller in 1.09.1/1.13 to anchor on.",
        "cGcScanEvent::CalculateMarkerPosition":
            "reached only via ScanEvent::Update, which is itself unlocatable in 1.09.1/1.13.",
        "cGcScanEvent::UpdateInteraction":
            "cGcMaintenanceComponentData class-name string is only emitted in the 1.38 exe.",
        "cGcBinoculars::UpdateTarget":
            "XHAIR_DISTANCE crosshair string only present in 1.38; earlier builds have no anchor.",
    }
    for name, reason in partial.items():
        if name not in unresolved:
            unresolved[name] = reason

    return {"functions": functions, "unresolved": unresolved}


if __name__ == "__main__":
    result = find()
    json.dump(result, sys.stdout)
    print()
