"""Finder for the ``hud_gui`` batch (cGcNGui* / cGcHUD* / cGcMarker* / marker funcs).

Deterministic, self-contained. Prints ONE JSON object to stdout; logs to stderr.

    python finders/find_hud_gui.py

Method notes (see HUNTING.md). The propagated_<build>.json / offsets.json maps give
legacy addresses for already-matched functions, used here as anchors. The legacy Ghidra
decompilation text encodes the call graph via ``FUN_<addr>`` tokens and inlines string
literals, so "who calls X" is a raw_decomp LIKE for FUN_<x> and "what does X call" is the
set of FUN_ tokens in X's decomp. Three targets resolve to two independent signals each;
the rest are reported unresolved with the reason.

Resolved
--------
* cGcNGuiText::EditElement    referrer-intersection of four distinctive, anchored callees
                              (cGcNGuiElement::EditElement + the cTkNGuiStyles/cTkNGuiEditor
                              edit helpers). Unique in every build; the 1.38 result equals
                              the curated offsets.json address, validating the method.
* cGcNGuiLayer::FindElementRecursive
                              the unique *recursive* function among the callees of this
                              target's anchored callers. Consistent size (250-272B) and
                              high ref-count across builds; sits in the same GcNGuiGenerator
                              TU as the layer ctor (adjacent addresses).
* cGcNGuiLayer::cGcNGuiLayer  version-stable ctor fingerprint: returns param_1, assigns two
                              distinct &PTR_FUN vtables, writes the 1.0f scale block at
                              +0xdc/+0xe4/+0xec/+0xf4 and clears +0x114. Exactly one match
                              per build; the decomp is near-identical 1.09.1->1.38.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import BUILDS, Binary  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OFFSETS = json.loads((ROOT.parents[1] / "nmspy" / "data" / "offsets.json").read_text())["functions"]
PROP = {b: json.loads((ROOT / "out" / f"propagated_{b}.json").read_text()) for b in BUILDS}
HINTS = json.loads((ROOT / "out" / "target_hints.json").read_text())

_bins = {}


def B(build):
    if build not in _bins:
        _bins[build] = Binary(build)
    return _bins[build]


def log(*a):
    print(*a, file=sys.stderr)


def anchor(build, name):
    """Legacy VA for a modern function name, from offsets.json then propagated."""
    e = OFFSETS.get(name)
    if isinstance(e, dict):
        v = e.get(build)
        if isinstance(v, str) and v.startswith("0x"):
            return int(v, 16)
    p = PROP[build].get(name)
    if p:
        return int(p["address"], 16)
    return None


def decomp(build, va):
    r = B(build).function_at(va)
    return r[3] if r else None


def size_at(build, va):
    r = B(build).function_at(va)
    return r[2] if r else None


def callees(build, va):
    d = decomp(build, va)
    if not d:
        return set()
    s = {int(x, 16) for x in re.findall(r"FUN_([0-9a-f]+)", d)}
    s.discard(va)  # strip the self-reference in the signature line
    return s


def referencers(build, va, limit=600):
    rows = B(build).functions_matching("%%FUN_%x%%" % va, limit)
    return [(a, n, s) for (n, a, s) in rows]


def refset(build, va, limit=600):
    return {a for (a, _n, _s) in referencers(build, va, limit)}


def is_recursive(build, va):
    d = decomp(build, va) or ""
    return d.count("FUN_%x" % va) >= 2


# --------------------------------------------------------------------------- #
# Derivations
# --------------------------------------------------------------------------- #

def derive_editelement():
    """cGcNGuiText::EditElement = intersection of referencers of its distinctive callees."""
    name = "cGcNGuiText::EditElement"
    callee_names = [
        "cGcNGuiElement::EditElement",
        "cTkNGuiStyles::EditGraphicStyle",
        "cTkNGuiStyles::EditTextStyle",
        "cTkNGuiEditor::DoEditFile",
    ]
    out = {}
    for build in BUILDS:
        sets = []
        for cn in callee_names:
            a = anchor(build, cn)
            if a is None:
                continue
            rs = refset(build, a)
            if len(rs) > 150:  # skip non-distinctive callees
                continue
            sets.append(rs)
        if len(sets) < 3:
            log(f"[EditElement] {build}: only {len(sets)} distinctive anchored callees")
            continue
        inter = set.intersection(*sets)
        if len(inter) == 1:
            va = next(iter(inter))
            if B(build).function_at(va):
                out[build] = "0x%X" % va
                log(f"[EditElement] {build}: {out[build]} (size {size_at(build, va)})")
                continue
        log(f"[EditElement] {build}: non-unique intersection {[hex(x) for x in inter]}")
    return name, out


def derive_find_element_recursive():
    """The unique recursive function among the callees of the target's anchored callers."""
    name = "cGcNGuiLayer::FindElementRecursive"
    callers = HINTS[name].get("modern_callers", [])
    out = {}
    for build in BUILDS:
        votes = {}
        used = 0
        for cn in callers:
            a = anchor(build, cn)
            if a is None:
                continue
            used += 1
            for x in callees(build, a):
                votes[x] = votes.get(x, 0) + 1
        rec = []
        for va, v in votes.items():
            if not B(build).function_at(va):
                continue
            if is_recursive(build, va):
                rec.append((v, len(refset(build, va)), va))
        rec.sort(reverse=True)
        if not rec:
            log(f"[FindElementRecursive] {build}: no recursive candidate (callers used {used})")
            continue
        # winner = most anchored-caller votes, tie-broken by ref-count
        if len(rec) == 1 or rec[0][:2] != rec[1][:2]:
            va = rec[0][2]
            out[build] = "0x%X" % va
            log(f"[FindElementRecursive] {build}: {out[build]} (votes {rec[0][0]}, "
                f"refs {rec[0][1]}, size {size_at(build, va)})")
        else:
            log(f"[FindElementRecursive] {build}: ambiguous {[hex(v) for _,_,v in rec[:3]]}")
    return name, out


CTOR_SIG = [
    "+ 0xdc) = 0x3f800000",
    "+ 0xe4) = 0x3f800000",
    "+ 0xec) = 0x3f800000",
    "+ 0xf4) = 0x3f800000",
    "+ 0x114) = 0",
]


def derive_nguilayer_ctor():
    """cGcNGuiLayer::cGcNGuiLayer via its version-stable ctor decomp fingerprint."""
    name = "cGcNGuiLayer::cGcNGuiLayer"
    out = {}
    for build in BUILDS:
        b = B(build)
        hits = []
        for (n, a, s) in b.functions_matching("%+ 0xdc) = 0x3f800000%", 400):
            d = b.function_at(a)[3]
            if all(fr in d for fr in CTOR_SIG) and d.count("&PTR_FUN_") >= 2:
                hits.append(a)
        if len(hits) == 1:
            va = hits[0]
            out[build] = "0x%X" % va
            log(f"[NGuiLayer::ctor] {build}: {out[build]} (size {size_at(build, va)})")
        else:
            log(f"[NGuiLayer::ctor] {build}: {len(hits)} hits {[hex(x) for x in hits]}")
    return name, out


# --------------------------------------------------------------------------- #

UNRESOLVED = {
    "cGcHUD::cGcHUD":
        "only anchored callee is a shared lambda_invoker (~28 referencers/build); no "
        "second signal to isolate this small ctor among them.",
    "cGcHUDManager::RemoveOSDMessage":
        "no modern signature/strings/callees/callers in target_hints; nothing to anchor on.",
    "cGcHUDManager::cGcHUDManager":
        "sole anchored callee is cGcNGuiLayer::cGcNGuiLayer (25-35 referencers); its own "
        "caller cGcApplication::Data ctor and the other member ctors are unmapped, so the "
        "referencer set cannot be narrowed to one.",
    "cGcHUDMarker::cGcHUDMarker":
        "anchored callees are the shared lambda_invoker plus (unmapped) cGcMarkerPoint::Reset "
        "and cGcNGui::cGcNGui; no distinctive anchor to intersect on.",
    "cGcMarkerList::RemoveMarker":
        "gcmarkerpoint.cpp cluster; only anchored caller is cGcCreatureComponent::Prepare "
        "(14KB, ~34 callees) and callees cGcMarkerPoint::IsEqual/operator= are unmapped.",
    "cGcMarkerList::TryAddMarker":
        "no anchored caller/callee; depends on the unmapped cGcMarkerPoint cluster.",
    "cGcMarkerPoint::Reset":
        "only anchored caller cGcCreatureComponent::Prepare has ~34 callees; the tiny-ctor "
        "signature that would isolate Reset is swamped by generic single-callee wrappers.",
    "cGcMarkerPoint::cGcMarkerPoint":
        "no anchored caller/callee; would follow from locating cGcMarkerPoint::Reset first.",
    "cGcNGuiElement::GetPosition":
        "tiny inlined accessor; caller-vote over 2-3 anchored callers does not converge to a "
        "unique small function (top hits are shared utilities/FindElementRecursive).",
    "cGcNGuiElement::Render":
        "virtual (called via vtable, no direct FUN_ callers) and its callees GetPosition/"
        "BeginUndo/EndUndo are unmapped; no anchor.",
    "cGcNGuiElement::SetPosition":
        "tiny inlined accessor; caller-vote does not converge to a unique function.",
    "cGcNGuiLayer::AddElement":
        "header-inline; callees are STL _Emplace_reallocate template bodies (unmapped) and "
        "caller-vote is non-unique.",
    "cGcNGuiLayer::FindTextRecursive":
        "header-inline thin wrapper around FindElementRecursive; FindElementRecursive has ~94 "
        "callers/build and no candidate carries the modern TkID hash, so it cannot be isolated.",
    "cGcNGuiLayer::GetGraphic":
        "one of four byte-identical templated accessor siblings next to the known "
        "cGcNGuiLayer::GetText; no structural feature distinguishes GetGraphic from its peers.",
    "cGcPositionMarker::Render":
        "references UI_UNIT_U which exists only in 1.38; the sole 1.38 referencer (0x1407931F0, "
        "526B) is the %DIST% unit-format helper, far too small for the 1846-len Render.",
}


def main():
    functions = {}
    for derive in (derive_editelement, derive_find_element_recursive, derive_nguilayer_ctor):
        name, per = derive()
        if per:
            functions[name] = per
    unresolved = {k: v for k, v in UNRESOLVED.items()}
    print(json.dumps({"functions": functions, "unresolved": unresolved}))


if __name__ == "__main__":
    main()
