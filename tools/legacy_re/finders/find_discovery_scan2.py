"""Finder (round 2) for the discovery_scan batch, cross-version extension.

Round 1 (finders/find_discovery_scan.py) located cGcScanEvent::Update,
CalculateMarkerPosition and UpdateInteraction only in the builds whose distinctive
gameplay strings still exist (TIMED_GOTO / cGcMaintenanceComponentData are 1.24/1.38
only). This round anchors the whole cGcScanEvent::Update callee cluster off a string
that IS present in every build and recovers the missing 1.09.1/1.13 (and 1.24
UpdateInteraction) addresses purely by call-graph structure.

Derivation (deterministic, verified against the curated 1.24/1.38 values):

  1. "SIGNAL_COMPLETE" has a single owner in 1.09.1/1.13/1.24 (two in 1.38); that owner
     is the scan-event signal-timer helper, a direct callee of cGcScanEvent::Update.
  2. cGcScanEvent::Update = the unique caller of a SIGNAL_COMPLETE owner that also calls
     an "INTERACT" owner (INTERACT is referenced by only ~9 functions binary-wide and by
     cGcScanEvent::CalculateMarkerPosition among them).
  3. In cGcScanEvent::Update's callee list sorted by address the scan-event methods are
     laid out in source order and sit consecutively:
         SIGNAL-owner -> UpdateInteraction -> CalculateMarkerPosition
     so UpdateInteraction and CalculateMarkerPosition are the next two callees after the
     SIGNAL owner. CalculateMarkerPosition is cross-checked to own "INTERACT".

  This reproduces the curated Update{1.24,1.38}, CalcMarker{1.24,1.38} and
  UpdateInteraction{1.38} exactly, and additionally yields:
    Update                 1.13 0x140ABF910, 1.09.1 0x140968A30
    CalculateMarkerPosition 1.13 0x140AC0B20, 1.09.1 0x140969A20
    UpdateInteraction      1.24 0x140C35270, 1.13 0x140AC03C0, 1.09.1 0x140969350
  UpdateInteraction 1.24/1.13/1.09.1 were decompile-verified (near-identical bodies:
  same DAT transform comparison, param+0x44==6 gate, marker-list build) and are distinct
  from CalculateMarkerPosition (param+0x44 state check + 0x3ffff marker-id sentinel).

Everything else in the batch has no usable anchor in any legacy build and is left
unresolved with the reason (see bottom).
"""

import json
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
from handles import Xverse  # noqa: E402


def log(*a):
    print(*a, file=sys.stderr)


def find():
    xv = Xverse()
    functions = {}
    unresolved = {}

    def put(name, build, addr):
        functions.setdefault(name, {})[build] = f"0x{addr:X}"

    sig_owners = xv.by_string("SIGNAL_COMPLETE")
    interact_owners = xv.by_string("INTERACT")

    for build in xv.builds:
        sig = set(sig_owners.get(build, []))
        interact = set(interact_owners.get(build, []))
        if not sig or not interact:
            log(f"{build}: missing SIGNAL_COMPLETE/INTERACT owners; skipping")
            continue

        # cGcScanEvent::Update = unique caller of a SIGNAL_COMPLETE owner that also
        # calls an INTERACT owner.
        cand = set()
        for so in sig:
            for c in xv.callers(build, so):
                kids = set(xv.callees(build, c))
                if so in kids and (kids & interact):
                    cand.add(c)
        if len(cand) != 1:
            log(f"{build}: Update not unique: {[hex(x) for x in cand]}")
            continue
        upd = next(iter(cand))

        kids = sorted(xv.callees(build, upd))
        so = next(k for k in kids if k in sig)
        i = kids.index(so)
        if i + 2 >= len(kids):
            log(f"{build}: no room after SIGNAL owner for the cluster")
            continue
        updint = kids[i + 1]
        calcm = kids[i + 2]

        # CalculateMarkerPosition must own INTERACT (sanity gate).
        if calcm not in interact:
            log(f"{build}: CalcMarker candidate 0x{calcm:X} does not own INTERACT; abort")
            continue

        # all three must be real function starts
        for a in (upd, updint, calcm):
            if xv.name(build, a) is None:
                log(f"{build}: 0x{a:X} not a function start; abort build")
                break
        else:
            put("cGcScanEvent::Update", build, upd)
            put("cGcScanEvent::UpdateInteraction", build, updint)
            put("cGcScanEvent::CalculateMarkerPosition", build, calcm)
            log(f"{build}: Update=0x{upd:X} UpdInt=0x{updint:X} CalcMkr=0x{calcm:X}")

    unresolved.update({
        "cGcScanEvent::Construct":
            "'list too long' string and the 0x0333333333333333 immediate are both absent "
            "from every legacy exe; the CalculateMarkerPosition call is inlined (CalcMarker "
            "has a single caller, Update) and callers cGcScanEventManager::AddEvent* are unmapped.",
        "cGcScanEvent::UpdateSpaceStationLocation":
            "SettlementConstructionLevel string absent from all four exes; its marker/base "
            "callees (cGcMarkerList::TryAddMarker, cGcBaseSearch::FindNearestBaseInCurrentSystem) "
            "are unmapped, so it cannot be picked out of the Update callee list by structure.",
        "cGcScanEventManager::PassesPlanetInfoChecks":
            "no strings/imm; sole callee cGcSolarSystem::DoesBuildingDensityHaveBuildingClass and "
            "sole caller cGcScanEventManager::CheckInterstellarEvent are unmapped in every build "
            "(profiler-name lookup returns nothing).",
        "cGcVisitedSystemsBuffer::VisitNewGalacticAddress":
            "no strings/imm; callees (ClassifyStarKeyAttributes, ClampToLimits) and caller "
            "(LoadGalacticAddressBuffers) are all unmapped and unrecoverable by profiler name.",
        "cGcDiscoveryManager::SubmitDiscoveryData":
            "62-byte wrapper over Data::SubmitDiscoveryData + cTkUnixTimestamp::Now; neither callee "
            "(both unmapped, no profiler-name hit) nor caller cGcSimpleInteractionComponent::DoAction "
            "(itself NOT_YET_FOUND) is anchorable.",
        "cGcBinoculars::GetRange":
            "float getter, no strings/imm; callee cGcSolarSystem::GetNearestPlanet unmapped; the "
            "callers that would anchor it (UpdateTarget/UpdateRayCasts/SetMarker) inline it in 1.38.",
        "cGcBinoculars::SetMarker":
            "only distinctive string cGcAtmosphereEntryComponentData is absent from all four exes; "
            "sole caller cGcPlayer::UpdateScanning is unmapped.",
        "cGcBinoculars::UpdateRayCasts":
            "decorated-name/source-path RTTI strings stripped in legacy; sole caller UpdateTarget "
            "does not call a raycast sub-function in 1.38 (logic still inlined pre-split).",
        "cGcBinoculars::UpdateScanBarProgress":
            "tiny lambda-wrapping helper, no strings/imm; only caller UpdateTarget does not call it "
            "in the 1.38 build (post-1.38 split); nothing to anchor on.",
        "cGcBinoculars::UpdateTarget":
            "curated only in 1.38 (XHAIR_DISTANCE, 1.38-only string); its caller (cGcBinoculars::"
            "Update) and gameplay callees are unmapped and its two real callees are generic "
            "number-format helpers, so it cannot be ported to 1.09.1/1.13/1.24.",
    })

    return {"functions": functions, "unresolved": unresolved}


if __name__ == "__main__":
    json.dump(find(), sys.stdout)
    print()
