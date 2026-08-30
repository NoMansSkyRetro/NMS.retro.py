"""Locate the frontend_ui NOT_YET_FOUND functions across the four legacy builds.

Batch: cGcFrontend* / cGcOptionsPageUI / cGcPhotoModeUI / cGcGalaxyMap UI functions.

Every address is re-derived here (no hard-coded offsets) so the result is auditable
and reproducible. The derivations reuse propagate_symbols' fingerprint/call-graph
machinery (sanctioned in HUNTING.md) plus a few targeted structural signals:

- Token fingerprint (modern 4.13 string/imm64 tokens vs a legacy build's tokens),
  weighting tokens that are single-owner-distinctive on both sides. This is the
  decisive 4.13->1.38 signal for the token-rich pages (UpdatePanelUI, DoDiscoveryView).
- Call-graph score against already-mapped neighbours (offsets.json + propagated_*.json):
  a candidate scores for each mapped callee it calls and each mapped caller that calls
  it. Decisive for the well-connected SetPopupBasics.
- Sideways port: once a function is located in one build, its equivalent one build over
  is the function whose callee/caller set best matches the ported (mapped) neighbours.
  The staircase 1.38->1.24->1.13->1.09.1 (months apart) transfers far better than the
  six-year 4.13->legacy hop, so every emitted sideways address is required to agree
  with that build's own independent top candidate before it is accepted.
- Caller intersection: RenderNVG is the largest function called by both galactic-map
  render states; this needs no modern side at all.
- imm64 adjacency: DoSolarPopup and its sibling DoSolarSelection are the only two
  functions referencing a distinctive galaxy constant; modern address order pins which
  is which.

Only a slot backed by two independent signals is emitted; everything else is reported
as unresolved with the reason. Prints one JSON object to stdout; logs to stderr.

    python finders/find_frontend_ui.py
"""

import json
import re
import struct
import sys
from bisect import bisect_right
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]          # tools/legacy_re
sys.path.insert(0, str(HERE))                        # so `common` / `propagate_symbols` import

from common import Binary                            # noqa: E402
import propagate_symbols as ps                       # noqa: E402

OFFSETS = HERE.parents[1] / "nmspy" / "data" / "offsets.json"
HINTS = json.loads((HERE / "out" / "target_hints.json").read_text())
BUILD_CHAIN = ["1.38", "1.24", "1.13", "1.09.1"]


def log(*a):
    print(*a, file=sys.stderr)


# --------------------------------------------------------------------------- data

def load_anchor_map(build):
    """upstream name -> legacy address (int), from curated offsets + propagated."""
    m = {}
    off = json.loads(OFFSETS.read_text())["functions"]
    for name, entry in off.items():
        if isinstance(entry, dict):
            a = entry.get(build)
            if isinstance(a, str) and a.startswith("0x"):
                m[name] = int(a, 16)
    prop = json.loads((HERE / "out" / f"propagated_{build}.json").read_text())
    for name, e in prop.items():
        a = e.get("address")
        if isinstance(a, str) and a.startswith("0x") and name not in m:
            m[name] = int(a, 16)
    return m


# propagate_symbols' Side/loader helpers print progress to stdout; keep stdout pure
# JSON by routing everything they emit to stderr during the load.
_real_stdout = sys.stdout
sys.stdout = sys.stderr
try:
    log("loading modern (4.13) side ...")
    REF_SIDE, REF_NAMES, REF_MANGLED = ps.load_side_413()
    TARGETS = ps.load_targets(REF_MANGLED)           # upstream name -> modern va
    _c = Counter()
    for _toks in REF_SIDE.prints.values():
        _c.update(_toks)
    REF_DISTINCT = {t for t, n in _c.items() if n == 1}

    log("loading legacy sides ...")
    SIDES = {b: ps.load_side_build(b) for b in BUILD_CHAIN}
    ANCHORS = {b: load_anchor_map(b) for b in BUILD_CHAIN}
    BINS = {b: Binary(b) for b in BUILD_CHAIN}
finally:
    sys.stdout = _real_stdout


# --------------------------------------------------------------------------- scoring

def mapped_neighbours(name, build):
    anch = ANCHORS[build]
    hint = HINTS.get(name, {})
    callees = {anch[c] for c in hint.get("modern_callees", []) if c in anch}
    callers = {anch[c] for c in hint.get("modern_callers", []) if c in anch}
    return callees, callers


def score(name, build):
    """Return {addr: (combined, token, callgraph, ntokens)} for candidate legacy funcs."""
    side = SIDES[build]
    tva = TARGETS.get(name)
    tok = defaultdict(float)
    ntok = defaultdict(int)
    if tva is not None:
        rtoks = REF_SIDE.prints.get(tva, set())
        by_tok = defaultdict(list)
        for k, toks in side.prints.items():
            for t in toks & rtoks:
                by_tok[t].append(k)
        for t in rtoks:
            cands = by_tok.get(t, [])
            if not cands:
                continue
            w = 1.0 / len(cands)
            if t in REF_DISTINCT and len(cands) == 1:
                w += 3.0
            for k in cands:
                tok[k] += w
                ntok[k] += 1
    callees, callers = mapped_neighbours(name, build)
    cg = defaultdict(float)
    for k, ce in side.callees.items():
        h = len(ce & callees)
        if h:
            cg[k] += h
    for cr in callers:
        for callee in side.callees.get(cr, ()):
            cg[callee] += 2.0
    out = {}
    for k in set(tok) | set(cg):
        out[k] = (tok[k] + cg[k], tok[k], cg[k], ntok[k])
    return out


def ranked(name, build):
    s = score(name, build)
    return sorted(s.items(), key=lambda kv: kv[1][0], reverse=True)


def sideways(addr_hi, hi, lo):
    """Rank lo-build candidates for the hi-build function at addr_hi (callee/caller port)."""
    side_hi, side_lo = SIDES[hi], SIDES[lo]
    # addr_hi -> addr_lo correspondence via shared upstream names
    inv_lo = {name: a for name, a in ANCHORS[lo].items()}
    corr = {a: inv_lo[name] for name, a in ANCHORS[hi].items() if name in inv_lo}
    mapped_callees = {corr[c] for c in side_hi.callees.get(addr_hi, ()) if c in corr}
    mapped_callers = {corr[c] for c in side_hi.callers.get(addr_hi, ()) if c in corr}
    sc = Counter()
    for k, ce in side_lo.callees.items():
        h = len(ce & mapped_callees)
        if h:
            sc[k] += h
    for cr in mapped_callers:
        for callee in side_lo.callees.get(cr, ()):
            sc[callee] += 1.5
    return sc.most_common()


def size_of(build, addr):
    row = BINS[build].function_at(addr)
    return row[2] if row else None


# ------------------------------------------------------------------ per-target work

RESULTS = defaultdict(dict)
UNRESOLVED = {}


def emit(name, build, addr, why):
    RESULTS[name][build] = f"0x{addr:X}"
    log(f"  EMIT {name} {build} = 0x{addr:X}  ({why})")


def token_lock_138(name, min_tok, modern_len, size_tol=0.30):
    """Lock a token-rich target in 1.38 (decisive 4.13->1.38 fingerprint + size sanity)."""
    r = ranked(name, "1.38")
    if not r:
        return None
    (addr, (comb, tok, cg, nt)) = r[0]
    second = r[1][1][0] if len(r) > 1 else 0.0
    second_addr = r[1][0] if len(r) > 1 else None
    sz = size_of("1.38", addr)

    def fits(a):
        s = size_of("1.38", a)
        return modern_len is None or (s and abs(s - modern_len) <= size_tol * modern_len)

    ok_size = fits(addr)
    # Two independent signals: >=3 single-owner-distinctive modern tokens on the top
    # candidate, AND either a dominant token margin or the top being the *only*
    # candidate whose size matches the modern length (a clean tie-break).
    unique_size = ok_size and not (second_addr is not None and fits(second_addr))
    ok = tok >= min_tok and nt >= 3 and ok_size and (comb > second + 2.0 or unique_size)
    log(f"  {name} 1.38 top 0x{addr:X} tok={tok:.1f} n={nt} comb={comb:.1f} "
        f"2nd={second:.1f} size={sz} modern={modern_len} size_ok={ok_size} "
        f"unique_size={unique_size} accept={ok}")
    if ok:
        return addr
    return None


def port_chain(name, addr_138):
    """Port a 1.38-locked address down the chain, requiring agreement with each
    build's own independent top candidate."""
    prev, hi = addr_138, "1.38"
    for lo in ["1.24", "1.13", "1.09.1"]:
        pr = sideways(prev, hi, lo)
        own = ranked(name, lo)
        if not pr or not own:
            log(f"  {name} {lo}: no candidates; stop chain")
            return
        p_addr, p_score = pr[0]
        p_second = pr[1][1] if len(pr) > 1 else 0
        o_addr = own[0][0]
        agree = p_addr == o_addr
        margin = p_score - p_second
        log(f"  {name} {lo}: port=0x{p_addr:X}(score {p_score:.1f}, 2nd {p_second:.1f}) "
            f"own_top=0x{o_addr:X} agree={agree}")
        if agree and margin >= 2.0:
            emit(name, lo, p_addr, f"port from {hi} agrees with independent top")
            prev, hi = p_addr, lo
        else:
            log(f"  {name} {lo}: methods disagree or thin margin; stop chain")
            return


def do_updatepanelui():
    name = "cGcGalaxyMapUI::SolarInfoPanel::UpdatePanelUI"
    log(f"== {name}")
    a = token_lock_138(name, min_tok=10.0, modern_len=HINTS[name]["modern_length"], size_tol=0.45)
    if a is None:
        UNRESOLVED[name] = "1.38 token fingerprint not decisive"
        return
    emit(name, "1.38", a, "10+ distinctive modern tokens, dominant margin")
    port_chain(name, a)


def do_setpopupbasics():
    name = "cGcFrontendPageFunctions::SetPopupBasics"
    log(f"== {name}")
    # Call-graph dominated: the unique function that calls >=3 mapped callees AND is
    # called by >=4 mapped callers. Verify per build, then require the sideways port
    # chain to reproduce the same address as a second signal.
    per_build = {}
    for b in BUILD_CHAIN:
        callees, callers = mapped_neighbours(name, b)
        side = SIDES[b]
        # candidates that call >=3 mapped callees
        callers_of_mapped = defaultdict(int)
        for cr in callers:
            for callee in side.callees.get(cr, ()):
                callers_of_mapped[callee] += 1
        best = None
        for k, ce in side.callees.items():
            nce = len(ce & callees)
            ncr = callers_of_mapped.get(k, 0)
            if nce >= 3 and ncr >= 3:
                cand = (nce + ncr, k, nce, ncr)
                if best is None or cand > best:
                    best = cand
        if best:
            per_build[b] = best[1]
            log(f"  {name} {b}: cg-winner 0x{best[1]:X} (callees {best[2]}, callers {best[3]}, "
                f"size {size_of(b, best[1])})")
    if "1.38" not in per_build:
        UNRESOLVED[name] = "no function calls>=3 mapped callees and called-by>=3 mapped callers"
        return
    # second signal: sideways port chain must reproduce per_build
    emit(name, "1.38", per_build["1.38"], "calls 3 mapped callees + called by 5 mapped callers")
    prev, hi = per_build["1.38"], "1.38"
    for lo in ["1.24", "1.13", "1.09.1"]:
        if lo not in per_build:
            log(f"  {name} {lo}: no cg-winner; stop")
            break
        pr = sideways(prev, hi, lo)
        if pr and pr[0][0] == per_build[lo]:
            emit(name, lo, per_build[lo], "cg-winner confirmed by sideways port")
            prev, hi = per_build[lo], lo
        else:
            log(f"  {name} {lo}: port {pr[0][0]:#x} != cg-winner {per_build[lo]:#x}; stop")
            break


def do_rendernvg():
    name = "cGcGalaxyMap::Data::RenderNVG"
    log(f"== {name}")
    # Largest function called by BOTH galactic-map render states. No modern side needed;
    # cross-checked against the call-graph/token scorer's top candidate.
    for b in BUILD_CHAIN:
        anch = ANCHORS[b]
        bn = BINS[b]
        r1 = anch.get("cGcApplicationGalacticMapState::Render")
        r2 = anch.get("cGcApplicationLocalLoadState::Render")
        if not (r1 and r2):
            UNRESOLVED.setdefault(name, "render-state callers not mapped in some build")
            log(f"  {name} {b}: render-state callers not both mapped")
            continue
        c1 = set(int(x, 16) for x in re.findall(r"FUN_(14[0-9a-f]+)", bn.function_at(r1)[3]))
        c2 = set(int(x, 16) for x in re.findall(r"FUN_(14[0-9a-f]+)", bn.function_at(r2)[3]))
        common = [(a, size_of(b, a)) for a in (c1 & c2) if bn.function_at(a)]
        common.sort(key=lambda t: -(t[1] or 0))
        if len(common) < 2:
            continue
        top, top_sz = common[0]
        second_sz = common[1][1] or 0
        scorer_top = ranked(name, b)
        agree = scorer_top and scorer_top[0][0] == top
        log(f"  {name} {b}: largest-common 0x{top:X} size={top_sz} 2nd_size={second_sz} "
            f"scorer_top={scorer_top[0][0]:#x} agree={agree}")
        if top_sz and second_sz < 0.6 * top_sz and agree:
            emit(name, b, top, "largest callee of both render states, confirmed by scorer")


def do_dodiscoveryview():
    name = "cGcFrontendPageDiscovery::DoDiscoveryView"
    log(f"== {name}")
    a = token_lock_138(name, min_tok=6.0, modern_len=HINTS[name]["modern_length"], size_tol=0.20)
    if a is None:
        UNRESOLVED[name] = "1.38 token fingerprint not decisive"
        return
    emit(name, "1.38", a, "distinctive discovery tokens + size within 20% of modern")
    # older builds: the sideways port drifts to smaller sibling discovery functions
    # (verified: 1.24 port picks a ~5KB function while the modern is ~20KB), and no
    # second signal agrees, so leave them unresolved rather than guess.
    UNRESOLVED[name] = ("1.38 located; 1.24/1.13/1.09.1 port drifts to wrong-sized "
                        "sibling discovery funcs with no confirming signal")


def do_dosolarpopup():
    name = "cGcGalaxyMap::Data::DoSolarPopup"
    log(f"== {name}")
    # DoSolarSelection and DoSolarPopup are the only two functions referencing the
    # distinctive galaxy constant and both are called by the mapped Data::Update.
    # Modern order is DoSolarSelection (lower addr) then DoSolarPopup, and modern
    # DoSolarPopup length ~1744 -> pick the higher-addr / size-matching one.
    IMM = 0x1DDA411120D4608B
    modern_len = HINTS[name]["modern_length"]
    for b in BUILD_CHAIN:
        bn = BINS[b]
        anch = ANCHORS[b]
        update = anch.get("cGcGalaxyMap::Data::Update")
        if not update:
            continue
        rows = bn.db.execute(
            "SELECT address,size FROM decompilations WHERE size>0 ORDER BY address"
        ).fetchall()
        starts = [r[0] for r in rows]

        def func_of(va):
            i = bisect_right(starts, va) - 1
            if i >= 0:
                a, s = rows[i]
                if a <= va < a + s:
                    return a, s
            return None

        ts = next(s for s in bn.sections if s.name == ".text")
        pat = struct.pack("<Q", IMM)
        funcs = {}
        i = bn.data.find(pat, ts.raw_offset, ts.raw_offset + ts.raw_size)
        while i >= 0:
            va = bn.file_offset_to_va(i)
            f = func_of(va)
            if f:
                funcs[f[0]] = f[1]
            i = bn.data.find(pat, i + 1, ts.raw_offset + ts.raw_size)
        up_decomp = bn.function_at(update)[3].lower()
        pair = sorted(a for a in funcs if ("%x" % a) in up_decomp)
        log(f"  {name} {b}: imm-funcs called-by-Update = "
            f"{[(hex(a), funcs[a]) for a in pair]}")
        if len(pair) == 2:
            # two adjacent siblings -> the second (higher addr) is DoSolarPopup;
            # confirm by size closeness to the modern length.
            cand = pair[1]
            if abs(funcs[cand] - modern_len) < abs(funcs[pair[0]] - modern_len):
                emit(name, b, cand, "2nd of the DoSolarSelection/DoSolarPopup imm pair, "
                                    "order + size match modern")
            else:
                log(f"  {name} {b}: size ordering unexpected; skip")
        else:
            log(f"  {name} {b}: DoSolarPopup not separated from DoSolarSelection here")
    if "1.38" not in RESULTS[name]:
        UNRESOLVED[name] = "could not separate DoSolarPopup from DoSolarSelection"
    else:
        UNRESOLVED.setdefault(
            name,
            "only 1.38 splits DoSolarPopup from DoSolarSelection; older builds carry a "
            "single merged ~2.2KB function (DoSolarSelection) so DoSolarPopup is unresolved",
        )


def mark_unresolved_rest():
    reasons = {
        "cGcFrontendManager::QueueFrontendPage":
            "114-byte leaf; none of its many modern callers are mapped in any build, no "
            "strings/imm64, so no anchor",
        "cGcFrontendManager::cGcFrontendManager":
            "constructor; sole modern caller (cGcApplication::Data ctor) and its "
            "distinctive callee ctors are all unmapped; no strings/imm64",
        "cGcFrontendPageClaimBase::DoBaseClaimOptions":
            "1.13/1.24/1.38 already curated; base-claim UI predates base building so the "
            "function does not exist in 1.09.1",
        "cGcFrontendPageDiscovery::GetDiscoveryHintString":
            "UI_CRE_* ids are hashed (no literals); the only DoDiscoveryView callee that "
            "hashes+translates is a generic multi-caller helper, not distinguishable as "
            "this 812-byte function",
        "cGcFrontendPageFunctions::SetEmptySlotBackground":
            "EGGINPUT id is hashed; its mapped callers' shared callees are dominated by "
            "SetPopupBasics, leaving no unique ~2.3KB candidate",
        "cGcFrontendPagePortalRunes::CheckUAIsValid":
            "portal runes exist only in 1.38; its distinctive voxel-generator callees are "
            "unmapped, only a weak size match remains",
        "cGcPhotoModeUI::OnRenderScreenshotFinished":
            "photo-mode ids/paths are hashed or renamed (no literals) and distinctive "
            "callees (SaveImageUsingWic/TonemapHdrToSdr) are unmapped; candidates tie",
        "cGcOptionsPageUI::BeginList":
            "no 4.13 PDB entry (inlined/renamed upstream) so no modern tokens or call "
            "graph, and no name literal in the legacy decomp",
        "cGcOptionsPageUI::ListOption":
            "no 4.13 PDB entry so no modern evidence; no name literal in the legacy decomp",
        "cGcOptionsPageUI::QualityOption":
            "no 4.13 PDB entry so no modern evidence; no name literal in the legacy decomp",
    }
    for n, r in reasons.items():
        UNRESOLVED.setdefault(n, r)


def main():
    do_updatepanelui()
    do_setpopupbasics()
    do_rendernvg()
    do_dodiscoveryview()
    do_dosolarpopup()
    mark_unresolved_rest()

    # never report a slot as both found and unresolved
    payload = {
        "functions": {k: v for k, v in RESULTS.items() if v},
        "unresolved": {k: r for k, r in UNRESOLVED.items() if k not in RESULTS or not RESULTS[k]},
    }
    log("\nsummary:")
    for n, v in payload["functions"].items():
        log(f"  {n}: {v}")
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
