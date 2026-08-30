#!/usr/bin/env python3
"""Finder for the ``hud_gui`` batch (round 2), NMS.retro.py legacy address hunt.

Prints ONE JSON object to stdout; all logging goes to stderr.

    {"functions": {"<name>": {"1.13": "0x...", ...}}, "unresolved": {"<name>": "reason"}}

Confirmed this round
--------------------
cGcNGuiLayer::GetGraphic  (all four builds)

    cGcNGuiLayer has a family of Get<Type>ByName accessors that share one body:
    FNV-1a hash the 16-byte TkID (basis 0xcbf29ce484222325), probe the element
    hash table at (this+0xb0), then call the element's virtual GetType() (vtable
    slot +8) and return the element only when the type enum matches, otherwise a
    static default element.  The accessors differ *only* by the enum they test:

        GetText   -> == 1   (already mapped as cGcNGuiLayer::GetText, our anchor)
        GetGraphic-> == 3

    The "Graphic == 3" identity is taken straight from the 4.13 reference
    decompilation of cGcNGuiLayer::GetGraphic (returns &mgDefaultGraphic, tests
    iVar3 == 3); GetText == 1 holds in every legacy build too, so the element-type
    enum is stable across versions and disc==3 is Graphic everywhere.

    Derivation (reproducible): from the already-mapped cGcNGuiLayer::GetText in
    each build, walk the address-adjacent siblings and pick the accessor whose
    GetType discriminator is ``== 3``.  Verified below by re-reading the body.

Everything else in the batch is left unresolved -- see the reasons dict.  The
key round-2 asks (cGcMarkerPoint::IsEqual and the marker ctor/Reset) could NOT
be locked: the cGcMarkerPoint struct diverged massively between 1.09-1.38 and
4.13 (413 IsEqual is a ~900B multi-clause comparison over mMission / mSequence /
meType switch / float-epsilon positions; 413 Reset clears cTkFixedString<64>/
<128> members that the early builds lay out differently), none of
cGcMarkerPoint / cGcMarkerList is present in the propagated 413->legacy maps to
anchor the compilation unit, and the marker functions are string-less.  This is
the same wall round 1 hit; documented per-target below.
"""

import json
import re
import sys
import bisect
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import Binary          # noqa: E402
from handles import Xverse         # noqa: E402


def log(*a):
    print(*a, file=sys.stderr)


# cGcNGuiLayer::GetText -- already curated in offsets.json, our per-build anchor
# into the accessor family.
GETTEXT = {
    "1.09.1": 0x1403CE620,
    "1.13":   0x1404A6970,
    "1.24":   0x1405585A0,
    "1.38":   0x14066BC40,
}

FNV_BASIS = "0xcbf29ce484222325"
DISC_RE = re.compile(r"==\s*(\d+)\)\)\s*\{[^}]*return")


def looks_like_accessor(dec: str) -> bool:
    """True for a cGcNGuiLayer Get<Type>ByName accessor body."""
    return FNV_BASIS in dec and "code **)(*" in dec


def find_getgraphic(xv, build):
    """Locate cGcNGuiLayer::GetGraphic (the accessor whose GetType test is ==3)."""
    gt = GETTEXT[build]
    B = Binary(build)
    funcs = xv.idx[build].funcs
    starts = [a for a, _ in funcs]
    i = bisect.bisect_left(starts, gt)

    # 1) sanity: the anchor really is the Text (==1) accessor
    gt_dec = B.function_at(gt)[3] or ""
    gt_disc = DISC_RE.findall(gt_dec)
    if gt_disc != ["1"]:
        log(f"[{build}] WARN GetText anchor {gt:#x} disc={gt_disc} (expected ['1'])")

    # 2) scan address-adjacent siblings first (cheap, usually a direct hit)
    for j in range(i - 6, i + 7):
        if 0 <= j < len(funcs):
            a, _ = funcs[j]
            dec = B.function_at(a)[3] or ""
            if looks_like_accessor(dec) and DISC_RE.findall(dec) == ["3"]:
                return a

    # 3) fall back to a binary-wide sweep of FNV-referencing accessors
    #    (1.09.1 splits the family: Graphic sits next to FindElementRecursive)
    for a in sorted(xv.idx[build].by_token.get(("imm", int(FNV_BASIS, 16)), ())):
        row = B.function_at(a)
        if not row:
            continue
        if not (240 <= row[2] <= 300):
            continue
        dec = row[3] or ""
        if looks_like_accessor(dec) and DISC_RE.findall(dec) == ["3"]:
            return a
    return None


def main():
    xv = Xverse()
    functions = {}

    gg = {}
    for build in ("1.09.1", "1.13", "1.24", "1.38"):
        va = find_getgraphic(xv, build)
        if va is None:
            log(f"[{build}] GetGraphic: not found")
            continue
        name = xv.name(build, va)
        if not name:
            log(f"[{build}] GetGraphic candidate {va:#x} is not a function start; skipping")
            continue
        log(f"[{build}] cGcNGuiLayer::GetGraphic = {va:#x} ({name})")
        # match offsets.json style: lowercase 0x prefix, uppercase hex digits
        gg[build] = "0x" + f"{va:X}"
    if gg:
        functions["cGcNGuiLayer::GetGraphic"] = gg

    unresolved = {
        "cGcMarkerPoint::IsEqual":
            "HIGH PRIORITY but not locked. 4.13 IsEqual is a ~900B multi-clause "
            "comparison (mMission/mSequence/meScannableType, switch on meType, node "
            "validity via Engine::GetNodeIsValid, float-epsilon position compare); the "
            "marker struct layout diverged too much from 1.09-1.38 to fingerprint by "
            "body, and no cGcMarkerPoint/cGcMarkerList symbol exists in the propagated "
            "413->legacy maps to anchor the CU. Adjacent NGuiLayer-region equality "
            "0x14066b420 (1.38) was checked and rejected (compares two objects at "
            "+0x50/base and strings at +0x200/+0x290 -> not the marker comparison).",
        "cGcMarkerPoint::cGcMarkerPoint":
            "Not locked. In 4.13 the ctor inlines field init (sets 3 node handles to "
            "0x3ffff, clears cTkFixedString<64/128> members) and does not survive as a "
            "distinct call target; no marker-CU anchor in the propagated maps. The "
            "ctor->Reset->cTkAttachmentPtr chain the hints imply could not be separated "
            "from the many scene-graph handle helpers that also reference 0x3ffff.",
        "cGcMarkerPoint::Reset":
            "Not locked. Reset is a direct callee of the mapped cGcCreatureComponent::"
            "Prepare, but the 0x3ffff-heavy callees of Prepare are all cTkSmartResHandle/"
            "cTkAttachmentPtr node resolvers (e.g. 1.38 0x141128870, 0x1410d11a0), not "
            "the marker field-reset; the true Reset sets a type enum and clears the "
            "embedded fixed-strings, which is not uniquely separable without a CU anchor.",
        "cGcMarkerList::TryAddMarker":
            "Not locked. 4.13 body is a std::vector<cGcMarkerPoint> scan (stride 0x280) "
            "calling IsEqual + operator= then _Emplace_reallocate; the per-version stride "
            "changes the division magic and none of cGcMarkerList is in the propagated "
            "maps, so there is no anchor and IsEqual (its key callee) is itself unfound.",
        "cGcMarkerList::RemoveMarker":
            "Not locked. Same wall as TryAddMarker: 4.13 RemoveMarker(cGcMarkerPoint&) "
            "scans the marker vector calling IsEqual and shifts with operator=, but with "
            "no mapped cGcMarkerList/cGcMarkerPoint anchor and IsEqual unfound it cannot "
            "be pinned. It is a direct callee of the mapped cGcCreatureComponent::Prepare "
            "but Prepare has ~30 callees and no distinctive-enough discriminator survived.",
        "cGcHUD::cGcHUD":
            "Not locked. Base HUD ctor; in 4.13 it lives in a dedicated ctor CU "
            "(0x140194BF0, clustered with cGcHUDManager/cGcPlayerHUD/cGcShipHUD/"
            "cGcHUDMarker ctors at 0x140194-0x140199) that has no mapped anchor in any "
            "legacy build; the mapped cGcPlayerHUD/cGcShipHUD methods (Construct/Render/"
            "LoadData) sit in different CUs and do not reach the ctors.",
        "cGcHUDManager::cGcHUDManager":
            "Not locked. Large ctor (4.13 ~626B) that constructs cGcNGui/cGcNGuiLayer/"
            "cGcInventoryStore/cGcQuickMenu/cGcPlayerHUD/cGcShipHUD and is called by the "
            "app ctor. It is a caller of the mapped cGcNGuiLayer::cGcNGuiLayer, but that "
            "ctor has ~34 callers in 1.38 and several ~500-730B ctor-shaped candidates; "
            "without cGcPlayerHUD/cGcShipHUD ctor or the app ctor mapped, the winner "
            "could not be disambiguated confidently.",
        "cGcHUDManager::RemoveOSDMessage":
            "Not locked. No profiler-name literal, no distinctive string, and no mapped "
            "cGcHUDManager anchor (only the unrelated *Data::ClassPointerSave symbols are "
            "in the propagated maps); the OSD message list op has no unique fingerprint.",
        "cGcHUDMarker::cGcHUDMarker":
            "Not locked. Calls cGcMarkerPoint::Reset and cGcNGui::cGcNGui; sits in the "
            "same ctor CU (4.13 0x1401995E0) as the other HUD ctors, far from the mapped "
            "cGcHUDMarker::LoadGuiFiles/Construct (4.13 0x14068C...), so LoadGuiFiles does "
            "not anchor it, and Reset (a key callee) is itself unfound.",
        "cGcPositionMarker::Render":
            "Not locked. References strings gameFont / UI_UNIT_U, but in the legacy exes "
            "UI_UNIT_U resolves to a distance/unit formatting helper (%DIST%/UI_UNIT_KS) "
            "and gameFont is shared by many functions; the real caller cGcPlayerHUD::"
            "RenderTrackArrows and callees (cGcInWorldUIManager::ActivateScreen etc.) are "
            "not mapped, so no single-owner string lock and no call-graph anchor.",
        "cGcNGuiElement::GetPosition":
            "Not locked. 4.13 body reads mpElementData->mLayout.mfPositionX/Y with UI "
            "layout float constants (1920.0/1080.0/0.01); returns cTkVector2. No mapped "
            "cGcNGuiElement anchor and 32-bit float immediates are not in the imm64 index, "
            "so it cannot be reached from the mapped NGuiLayer/NGuiText symbols.",
        "cGcNGuiElement::SetPosition":
            "Not locked. The (float,float,PositionType) overload is a 34B forwarder that "
            "tail-calls the (cTkVector2*,PositionType) SetPosition -- far too generic a "
            "shape to identify uniquely with no cGcNGuiElement CU anchor.",
        "cGcNGuiElement::Render":
            "Not locked. Base virtual Render (4.13 ~1217B) invoked by the derived "
            "NGuiText/NGuiLayer/NGuiGraphic/NGuiSpacing/NGuiTextSpecial Render methods, "
            "none of which are mapped; its callees (cTkNGuiEditor::Begin/EndUndo, "
            "GetPosition) are also unmapped, leaving no anchor.",
        "cGcNGuiLayer::AddElement":
            "Not locked. 4.13 AddElement (0x140214830, 155B) push_backs into this->"
            "mapElements then calls the element vtable slots +0x50 and +0x68 and "
            "conditionally push_backs a sublayer. It lives in a different CU from the "
            "mapped Get*/Find* accessors (4.13 0x1401C...), its callers "
            "(cGcNGuiLayer::SetData, cGc*Option::Initialize) are not mapped, and a 1.38 "
            "scan for the +0x50/+0x68 twin-vtable-push fingerprint yielded no candidate.",
        "cGcNGuiLayer::FindTextRecursive":
            "Not locked. 4.13 hashes the TkID and calls FindElementRecursive(this, id, "
            "eGuiElement_Text). In the legacy builds the standalone wrapper does not "
            "isolate: FindElementRecursive has hundreds of callers, the small FNV-hashing "
            "callers are the cGcNGuiManager-level page/layer recursion loops (iterating "
            "this+0x200d0), and the flat GetText accessor covers the same lookup, so a "
            "distinct cGcNGuiLayer::FindTextRecursive could not be pinned.",
    }

    # Drop any unresolved entry we actually resolved.
    for k in list(unresolved):
        if k in functions:
            del unresolved[k]

    print(json.dumps({"functions": functions, "unresolved": unresolved}))


if __name__ == "__main__":
    main()
