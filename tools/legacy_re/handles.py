"""Cross-version function-finding toolkit for the legacy builds.

The fleet's slow part was every agent rebuilding the same indices. This module builds
them once, caches them to disk (keyed by the decomp DB's mtime), and exposes a small
API for locating a function and porting it across all four builds.

Quick start (from tools/legacy_re/):

    from handles import Xverse
    xv = Xverse()                       # loads/builds caches for all builds

    xv.by_string("CRUISE: Max Boost")   # {build: [addrs]} referencing that string
    xv.port("1.38", 0x1408F5620)        # {build: addr} same function in every build
    xv.callers("1.13", 0x140D4B460)     # addrs that call this function
    xv.callees("1.13", 0x140D4B460)     # functions this one calls
    xv.neighbours("1.13", 0x140D4B460)  # address-adjacent funcs (same compilation unit)
    xv.name("1.38", 0x1408F5620)        # Ghidra name (usually FUN_...) + size

Indices per build:
  strings:  va -> text  (rdata/data ASCII)
  xrefs:    func_addr -> {referenced string texts} | {("imm", value)}
  by_token: token -> {func_addrs}         (reverse of xrefs)
  callees:  func_addr -> {called func_addrs}
  callers:  func_addr -> {calling func_addrs}
  funcs:    sorted [(addr, size)]

`port` works by intersecting *distinctive* tokens (referenced by exactly one function
in each build), then, if that is ambiguous, by call-graph neighbourhood against an
anchor map (offsets.json + propagated). Locate a function in one build (usually 1.38,
closest to the 4.13 PDB), then port sideways.
"""

import json
import pickle
import re
import struct
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

import numpy as np

from common import BUILDS, STATIC_BASE, Binary

CACHE = Path(__file__).parent / "out" / "cache"
OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"
MIN_STRING_LEN = 5


def _extract_strings(data, sections):
    out = {}
    for name, va, vsize, raw, rsize in sections:
        if name not in (".rdata", ".data", "_RDATA"):
            continue
        blob = data[raw : raw + rsize]
        pos = 0
        while True:
            end = blob.find(b"\0", pos)
            if end == -1:
                break
            chunk = blob[pos:end]
            if len(chunk) >= MIN_STRING_LEN and all(0x20 <= c < 0x7F for c in chunk):
                out[STATIC_BASE + va + pos] = chunk.decode("ascii")
            pos = end + 1
    return out


class BuildIndex:
    def __init__(self, build):
        self.build = build
        b = Binary(build)
        self.data = b.data
        self.sections = [
            (s.name, s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size)
            for s in b.sections
        ]
        self.funcs = sorted(
            (addr, size) for addr, size in b.db.execute("SELECT address, size FROM decompilations")
        )
        self._names = None
        self._db_path = BUILDS[build][1]
        self._build_indices()

    # ---- containing-function lookup ----
    def containing(self, va):
        starts = self._starts
        i = bisect_right(starts, va) - 1
        if i >= 0:
            addr, size = self.funcs[i]
            if addr <= va < addr + size:
                return addr
        return None

    def _text(self):
        return next(s for s in self.sections if s[0] == ".text")

    def _build_indices(self):
        self._starts = [f[0] for f in self.funcs]
        strings = _extract_strings(self.data, self.sections)
        self.strings = strings
        _, tva, _, traw, trsize = self._text()
        text_va = STATIC_BASE + tva

        xrefs = defaultdict(set)
        # string rel32 refs
        vas = np.array(sorted(strings), dtype=np.int64)
        tdata = np.frombuffer(self.data, dtype=np.uint8, count=trsize, offset=traw)
        for start in range(0, trsize - 4, 1 << 22):
            stop = min(start + (1 << 22), trsize - 4)
            bb = tdata[start : stop + 3]
            i32 = (
                bb[0:-3].astype(np.uint32)
                | (bb[1:-2].astype(np.uint32) << 8)
                | (bb[2:-1].astype(np.uint32) << 16)
                | (bb[3:].astype(np.uint32) << 24)
            ).astype(np.int32)
            pos_va = text_va + start + np.arange(len(i32), dtype=np.int64)
            targets = pos_va + 4 + i32
            idx = np.searchsorted(vas, targets)
            hit = (idx < len(vas)) & (vas[np.minimum(idx, len(vas) - 1)] == targets)
            for p in np.nonzero(hit)[0]:
                fn = self.containing(text_va + start + int(p))
                if fn is not None:
                    xrefs[fn].add(strings[int(targets[p])])
        # imm64 refs
        rex = (tdata[:-9] == 0x48) | (tdata[:-9] == 0x49)
        opc = (tdata[1:-8] >= 0xB8) & (tdata[1:-8] <= 0xBF)
        for p in np.nonzero(rex & opc)[0]:
            imm = int.from_bytes(self.data[traw + p + 2 : traw + p + 10], "little")
            if imm < 0x10000 or 0x140000000 <= imm < 0x150000000:
                continue
            fn = self.containing(text_va + int(p))
            if fn is not None:
                xrefs[fn].add(("imm", imm))
        self.xrefs = dict(xrefs)

        by_token = defaultdict(set)
        for fn, toks in self.xrefs.items():
            for t in toks:
                by_token[t].add(fn)
        self.by_token = dict(by_token)
        self.distinctive = {t for t, fns in by_token.items() if len(fns) == 1}

        # call edges
        callees = defaultdict(set)
        callers = defaultdict(set)
        starts_arr = np.array(self._starts, dtype=np.int64)
        is_call = (tdata[:-5] == 0xE8) | (tdata[:-5] == 0xE9)
        pos = np.nonzero(is_call)[0]
        i32 = (
            tdata[pos + 1].astype(np.uint32)
            | (tdata[pos + 2].astype(np.uint32) << 8)
            | (tdata[pos + 3].astype(np.uint32) << 16)
            | (tdata[pos + 4].astype(np.uint32) << 24)
        ).astype(np.int32)
        targets = text_va + pos.astype(np.int64) + 5 + i32
        idx = np.searchsorted(starts_arr, targets)
        hit = (idx < len(starts_arr)) & (starts_arr[np.minimum(idx, len(starts_arr) - 1)] == targets)
        for p, t in zip(pos[hit], targets[hit]):
            fn = self.containing(text_va + int(p))
            if fn is not None:
                callees[fn].add(int(t))
                callers[int(t)].add(fn)
        self.callees = dict(callees)
        self.callers = dict(callers)
        # Hubs: library stubs / allocators called by a huge number of functions
        # (__security_check_cookie, memcpy, operator new). They pollute call-graph
        # matching, so exclude them as candidates.
        self.hubs = {fn for fn, cs in callers.items() if len(cs) > 500}

    def names(self):
        if self._names is None:
            b = Binary(self.build)
            self._names = {
                addr: (name, size)
                for name, addr, size in b.db.execute(
                    "SELECT name, address, size FROM decompilations"
                )
            }
        return self._names

    # ---- cache ----
    _FIELDS = ("funcs", "strings", "xrefs", "by_token", "distinctive", "callees", "callers", "hubs")

    def to_cache(self):
        CACHE.mkdir(parents=True, exist_ok=True)
        mtime = Path(self._db_path).stat().st_mtime_ns
        payload = {"mtime": mtime, "starts": self._starts}
        payload.update({f: getattr(self, f) for f in self._FIELDS})
        with open(CACHE / f"{self.build}.pkl", "wb") as fh:
            pickle.dump(payload, fh, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def from_cache(cls, build):
        path = CACHE / f"{build}.pkl"
        if not path.exists():
            return None
        with open(path, "rb") as fh:
            payload = pickle.load(fh)
        if payload["mtime"] != Path(BUILDS[build][1]).stat().st_mtime_ns:
            return None
        self = cls.__new__(cls)
        self.build = build
        self._db_path = BUILDS[build][1]
        self._names = None
        b = Binary(build)
        self.data = b.data
        self.sections = [
            (s.name, s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size)
            for s in b.sections
        ]
        self._starts = payload["starts"]
        for f in cls._FIELDS:
            setattr(self, f, payload[f])
        return self


class Xverse:
    """All build indices plus the cross-version operations."""

    ORDER = ["1.38", "1.24", "1.13", "1.09.1"]  # newest first (closest to 4.13 PDB)

    def __init__(self, builds=None, verbose=True):
        self.builds = builds or [b for b in self.ORDER if b in BUILDS]
        self.idx = {}
        for b in self.builds:
            ix = BuildIndex.from_cache(b)
            if ix is None:
                if verbose:
                    print(f"[handles] building index for {b} ...", flush=True)
                ix = BuildIndex(b)
                ix.to_cache()
            self.idx[b] = ix
        self._offsets = json.loads(OFFSETS.read_text())["functions"]
        self._corr = self._load_correspondence()

    def _load_correspondence(self):
        """(build_a, build_b) -> {addr_a: addr_b}, from the propagated 4.13->build maps
        plus every offsets.json function mapped in >1 build. Thousands of known
        cross-build function correspondences to anchor call-graph porting."""
        per413 = defaultdict(dict)  # 4.13 key -> {build: addr}
        out_dir = Path(__file__).parent / "out"
        for b in self.builds:
            path = out_dir / f"propagated_{b}.json"
            if not path.exists():
                continue
            for name, info in json.loads(path.read_text()).items():
                addr = info.get("address")
                if addr:
                    per413[name][b] = int(addr, 16)
        # offsets.json: use the name as the shared key across builds
        for name, entry in self._offsets.items():
            for b in self.builds:
                v = entry.get(b)
                if isinstance(v, str) and v.startswith("0x"):
                    per413[f"off::{name}"][b] = int(v, 16)
        corr = defaultdict(dict)
        for mapping in per413.values():
            for ba, aa in mapping.items():
                for bb, ab in mapping.items():
                    if ba != bb:
                        corr[(ba, bb)][aa] = ab
        return corr

    # ---- primitives ----
    def name(self, build, va):
        return self.idx[build].names().get(va)

    def is_func(self, build, va):
        return any(a == va for a, _ in self.idx[build].funcs)

    def callers(self, build, va):
        return sorted(self.idx[build].callers.get(va, ()))

    def callees(self, build, va):
        return sorted(self.idx[build].callees.get(va, ()))

    def strings_of(self, build, va):
        return sorted(t for t in self.idx[build].xrefs.get(va, ()) if isinstance(t, str))

    def neighbours(self, build, va, n=3):
        funcs = self.idx[build].funcs
        starts = self.idx[build]._starts
        i = bisect_right(starts, va) - 1
        lo, hi = max(0, i - n), min(len(funcs), i + n + 1)
        return [a for a, _ in funcs[lo:hi]]

    def by_string(self, text, exact=True):
        """{build: [func addrs]} referencing a given string (exact token or substring)."""
        out = {}
        for b, ix in self.idx.items():
            if exact:
                out[b] = sorted(ix.by_token.get(text, ()))
            else:
                hits = set()
                for tok, fns in ix.by_token.items():
                    if isinstance(tok, str) and text in tok:
                        hits |= fns
                out[b] = sorted(hits)
        return out

    def anchor_map(self, name):
        """upstream/known name -> {build: va} from offsets.json (addresses only)."""
        entry = self._offsets.get(name, {})
        return {
            b: int(v, 16)
            for b, v in entry.items()
            if b in self.builds and isinstance(v, str) and v.startswith("0x")
        }

    # ---- porting ----
    def port(self, src_build, va):
        """{build: addr} for the same function across builds, high precision.

        Returns a build only when the evidence is strong enough to trust without
        manual verification: the distinctive-token winner and the call-graph winner
        AGREE, or one method is overwhelming on its own (>=3 shared distinctive
        tokens, or a call-graph match with a wide margin). Ambiguous builds are
        omitted rather than guessed (use port_candidates for leads). The source build
        maps to itself.
        """
        src = self.idx[src_build]
        src_tokens = src.xrefs.get(va, set())
        out = {src_build: va}
        for b, ix in self.idx.items():
            if b == src_build:
                continue
            # string/imm winner
            votes = defaultdict(int)
            for t in src_tokens:
                if t in src.distinctive and t in ix.distinctive:
                    (fn,) = ix.by_token[t]
                    votes[fn] += 1
            str_win, str_n = None, 0
            if votes:
                best = max(votes.values())
                winners = [fn for fn, v in votes.items() if v == best]
                if len(winners) == 1:
                    str_win, str_n = winners[0], best
            cg_win = self._port_by_callgraph(src_build, va, b)
            if str_win is not None and str_win == cg_win:
                out[b] = str_win           # two independent methods agree
            elif str_n >= 3:
                out[b] = str_win           # overwhelming string evidence alone
            elif str_win is None and cg_win is not None:
                out[b] = cg_win            # call-graph only (already strict: >=5, margin>=3)
        return out

    def _port_by_callgraph(self, src_build, va, dst_build, min_shared=5):
        corr = self._corr.get((src_build, dst_build), {})
        if not corr:
            return None
        src = self.idx[src_build]
        dst = self.idx[dst_build]
        # Expected neighbour addresses in dst, from src's mapped neighbours.
        exp_callees = {corr[c] for c in src.callees.get(va, ()) if c in corr}
        exp_callers = {corr[c] for c in src.callers.get(va, ()) if c in corr}
        if len(exp_callees) + len(exp_callers) < min_shared:
            return None
        # Exclude hubs (allocators/library stubs called by hundreds of functions) and
        # tiny library stubs (e.g. __security_check_cookie, 31 B) as candidates.
        hubs = getattr(dst, "hubs", set())
        size_of = dict(dst.funcs)
        ok = lambda f: f not in hubs and size_of.get(f, 0) >= 48
        scores = defaultdict(lambda: [0, 0])  # func -> [callee_overlap, caller_overlap]
        for callee in exp_callees:
            for f in dst.callers.get(callee, ()):
                if ok(f):
                    scores[f][0] += 1
        for caller in exp_callers:
            for f in dst.callees.get(caller, ()):
                if ok(f):
                    scores[f][1] += 1
        if not scores:
            return None
        # Total score, but require BOTH directions to agree when both are available,
        # so adjacent siblings (which share callers but not the exact callee set) don't
        # win by one side alone.
        totals = {f: s[0] + s[1] for f, s in scores.items()}
        ranked = sorted(totals.items(), key=lambda kv: -kv[1])
        best_f, best = ranked[0]
        second = ranked[1][1] if len(ranked) > 1 else 0
        # High-precision gate: strong absolute support and a clear margin over the
        # runner-up (a lone winner with margin<2 is usually one of two adjacent
        # siblings sharing a caller set, so we abstain rather than risk a wrong port).
        if best < min_shared or best - second < 2:
            return None
        return best_f

    def port_candidates(self, src_build, va, topn=3):
        """{build: [(addr, score, why), ...]} ranked candidates per build.

        Unlike port(), this never abstains: it returns the best guesses with evidence
        so an agent can decompile and confirm. Combines distinctive-token votes and
        correspondence-anchored call-graph overlap. The source build returns [(va, ...)].
        """
        src = self.idx[src_build]
        src_tokens = src.xrefs.get(va, set())
        out = {src_build: [(va, 999, "source")]}
        for b, ix in self.idx.items():
            if b == src_build:
                continue
            score = defaultdict(int)
            why = defaultdict(list)
            for t in src_tokens:
                if t in src.distinctive and t in ix.distinctive:
                    (fn,) = ix.by_token[t]
                    score[fn] += 3
                    why[fn].append(f"str:{t if isinstance(t, str) else 'imm'}")
            corr = self._corr.get((src_build, b), {})
            exp_callees = {corr[c] for c in src.callees.get(va, ()) if c in corr}
            exp_callers = {corr[c] for c in src.callers.get(va, ()) if c in corr}
            for callee in exp_callees:
                for f in ix.callers.get(callee, ()):
                    score[f] += 1
                    why[f].append("callee")
            for caller in exp_callers:
                for f in ix.callees.get(caller, ()):
                    score[f] += 1
                    why[f].append("caller")
            ranked = sorted(score.items(), key=lambda kv: -kv[1])[:topn]
            out[b] = [(f, s, "+".join(sorted(set(why[f])))) for f, s in ranked]
        return out

    def port_via_anchor(self, src_build, va, anchor_name):
        """Port using an already-mapped function as a call-graph landmark.

        If `va` in src_build is the unique caller (or callee) of the anchor, find the
        function in each build with the same relation to that build's anchor address.
        Returns {build: addr}. Useful when strings don't survive.
        """
        amap = self.anchor_map(anchor_name)
        out = {}
        src = self.idx[src_build]
        anchor_src = amap.get(src_build)
        if anchor_src is None:
            return out
        rel = None
        if va in src.callers.get(anchor_src, ()):
            rel = "callers"
        elif va in src.callees.get(anchor_src, ()):
            rel = "callees"
        if rel is None:
            return out
        for b, ix in self.idx.items():
            anc = amap.get(b)
            if anc is None:
                continue
            cands = getattr(ix, rel).get(anc, set())
            if b == src_build:
                out[b] = va
            elif len(cands) == 1:
                out[b] = next(iter(cands))
        return out

    def find_by_profiler_name(self, cpp_name):
        """{build: [addrs]} whose decomp embeds the literal "cpp_name" (strncpy self-name)."""
        out = {}
        for b, ix in self.idx.items():
            out[b] = sorted(ix.by_token.get(cpp_name, ()))
        return out


if __name__ == "__main__":
    import sys

    xv = Xverse()
    if len(sys.argv) >= 3 and sys.argv[1] == "port":
        build, va = sys.argv[2], int(sys.argv[3], 16)
        ported = xv.port(build, va)
        for b in xv.builds:
            print(f"{b}: " + (f"0x{ported[b]:X}" if b in ported else "-"))
    elif len(sys.argv) >= 3 and sys.argv[1] == "string":
        for b, addrs in xv.by_string(sys.argv[2]).items():
            print(f"{b}: " + ", ".join(f"0x{a:X}" for a in addrs))
    else:
        print("caches ready for:", ", ".join(xv.builds))
