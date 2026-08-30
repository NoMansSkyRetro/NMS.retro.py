"""Propagate the functions NMS.py supported on 4.13 to the legacy builds.

The goal is coverage of upstream NMS.py's own hook surface — the 331 functions in its
tools/data.json (bundled here as ``upstream_data_413.json``) — not the whole PDB.
Modern byte signatures do not survive six years of compiler and code drift (see
try_modern_signatures.py for the numbers), so functions are matched structurally:

1. **Fingerprints.** Every side (the 4.13 exe with its PDB dump, each legacy exe with
   its Ghidra DB) gets per-function token sets: referenced string literals plus
   ``mov reg, imm64`` constants (TkID hashes are stable across versions). A token
   referenced by exactly one function per side is *distinctive*; functions sharing
   distinctive tokens match when the pairing is unique both ways with at least
   ``--min-votes`` shared tokens.
2. **Call-graph expansion.** Matches grow iteratively: unmatched functions vote via
   co-occurrence as callees/callers of matched pairs, and the classic diffing rule
   applies (a matched pair with exactly one unmatched neighbour on each side pairs
   them). Mutual-unique best wins.
3. **The staircase.** The 4.13 -> 1.38 hop is the hard one (six years apart); the
   legacy builds are months apart, so 1.38 -> 1.24 -> 1.13 [-> 1.09.1] matches
   cascade with far higher yield. Maps are composed along the chain, so a function
   only needs to survive the hard hop once.

Matched upstream-surface functions are merged into nmspy/data/offsets.json under
upstream's names (curated entries always win; conflicts are reported and kept);
every match is written to ``out/propagated_<build>.json`` with its evidence.

    python propagate_symbols.py [--write] [--min-votes N] [--builds 1.38,1.24,1.13]
"""

import json
import struct
import sys
from bisect import bisect_right
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from common import BUILDS, STATIC_BASE, Binary

EXE_413 = r"E:\AI_NMS_DISASM\NMS413_PDBAGENT\original_exe_lib_exp_pdb\NMS.exe"
REF_413 = r"E:\AI_NMS_DISASM\NMS1091_GHIDRA_ANALYSIS\reference_symbol_db.json"
TARGETS = Path(__file__).parent / "upstream_data_413.json"
OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"
OUT = Path(__file__).parent / "out"

MIN_STRING_LEN = 6
CHUNK = 1 << 22
DEFAULT_CHAIN = ["1.38", "1.24", "1.13", "1.09.1"]


def parse_sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    out = []
    for o in range(pe + 24 + opt, pe + 24 + opt + nsec * 40, 40):
        name = data[o : o + 8].rstrip(b"\0").decode()
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, o + 8)
        out.append((name, va, vsize, raw, rsize))
    return out


def extract_strings(data, sections):
    """VA -> string text, for NUL-terminated printable ASCII in rdata/data."""
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
                out[STATIC_BASE + va + pos] = chunk
            pos = end + 1
    return out


def string_refs(data, sections, string_vas):
    """Yield (file_offset, target_va) for every rel32 in .text hitting a string."""
    vas = np.array(sorted(string_vas), dtype=np.int64)
    for name, va, vsize, raw, rsize in sections:
        if name != ".text":
            continue
        text = np.frombuffer(data, dtype=np.uint8, count=rsize, offset=raw)
        for start in range(0, rsize - 4, CHUNK):
            stop = min(start + CHUNK, rsize - 4)
            b = text[start : stop + 3]
            i32 = (
                b[0:-3].astype(np.uint32)
                | (b[1:-2].astype(np.uint32) << 8)
                | (b[2:-1].astype(np.uint32) << 16)
                | (b[3:].astype(np.uint32) << 24)
            ).astype(np.int32)
            pos_va = STATIC_BASE + va + start + np.arange(len(i32), dtype=np.int64)
            targets = pos_va + 4 + i32
            idx = np.searchsorted(vas, targets)
            hit = (idx < len(vas)) & (vas[np.minimum(idx, len(vas) - 1)] == targets)
            for p in np.nonzero(hit)[0]:
                yield raw + start + int(p), int(targets[p])


def imm64_refs(data, sections):
    """Yield (file_offset, imm) for every `mov reg, imm64` (REX.W B8+r) in .text.

    NMS embeds TkID FNV hashes as 64-bit immediates; they are stable across game
    versions, which makes them excellent fingerprint tokens for functions that
    reference few strings.
    """
    for name, va, vsize, raw, rsize in sections:
        if name != ".text":
            continue
        text = np.frombuffer(data, dtype=np.uint8, count=rsize, offset=raw)
        rex = (text[:-9] == 0x48) | (text[:-9] == 0x49)
        opc = (text[1:-8] >= 0xB8) & (text[1:-8] <= 0xBF)
        for p in np.nonzero(rex & opc)[0]:
            imm = int.from_bytes(data[raw + p + 2 : raw + p + 10], "little")
            # Skip trivially common values and in-image addresses.
            if imm < 0x10000 or 0x140000000 <= imm < 0x150000000:
                continue
            yield raw + int(p), imm


class Side:
    """One binary with function bounds: fingerprints and call graph."""

    def __init__(self, label, data, sections, functions):
        self.label = label
        self.functions = sorted(functions)  # (start_va, size, key) with key == start_va
        starts = [f[0] for f in self.functions]

        def containing(va):
            i = bisect_right(starts, va) - 1
            if i >= 0:
                start, size, key = self.functions[i]
                if start <= va < start + size:
                    return key
            return None

        text = next(s for s in sections if s[0] == ".text")
        text_raw, text_va = text[3], STATIC_BASE + text[1]

        strings = extract_strings(data, sections)
        self.prints = defaultdict(set)
        for off, target in string_refs(data, sections, strings.keys()):
            key = containing(text_va + (off - text_raw))
            if key is not None:
                self.prints[key].add(strings[target])
        for off, imm in imm64_refs(data, sections):
            key = containing(text_va + (off - text_raw))
            if key is not None:
                self.prints[key].add(("imm", imm))

        counts = Counter()
        for tokens in self.prints.values():
            counts.update(tokens)
        self.distinctive = {t for t, n in counts.items() if n == 1}

        self.callees = defaultdict(set)
        self.callers = defaultdict(set)
        starts_arr = np.array(starts, dtype=np.int64)
        tdata = np.frombuffer(data, dtype=np.uint8, count=text[4], offset=text_raw)
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
            key = containing(text_va + int(p))
            if key is not None:
                self.callees[key].add(int(t))
                self.callers[int(t)].add(key)
        print(
            f"{label}: {len(self.functions)} functions, "
            f"{len(self.prints)} with tokens, {len(self.callees)} with calls"
        )


def load_side_413():
    data = open(EXE_413, "rb").read()
    sections = parse_sections(data)
    ref = json.load(open(REF_413))
    funcs, names, mangled = [], {}, {}
    for f in ref["functions"]:
        va = STATIC_BASE + f["rva"]
        funcs.append((va, f.get("length") or 0x10000, va))
        names[va] = f.get("undecorated_name") or f["name"]
        mangled[f["name"]] = va
    return Side("4.13", data, sections, funcs), names, mangled


def load_side_build(build):
    b = Binary(build)
    funcs = [
        (addr, size, addr)
        for addr, size in b.db.execute("SELECT address, size FROM decompilations")
    ]
    sections = [
        (s.name, s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size)
        for s in b.sections
    ]
    return Side(build, b.data, sections, funcs)


def match_sides(A: Side, B: Side, seed: dict, min_votes: int) -> dict:
    """A_key -> B_key matches from fingerprints + call-graph expansion."""
    shared = A.distinctive & B.distinctive
    a_by_token = {}
    for key, tokens in A.prints.items():
        for t in tokens & shared:
            a_by_token[t] = key
    votes = Counter()
    for key, tokens in B.prints.items():
        for t in tokens & shared:
            votes[(a_by_token[t], key)] += 1

    a_best = defaultdict(list)
    b_best = defaultdict(list)
    for (a, bk), n in votes.items():
        a_best[a].append((bk, n))
        b_best[bk].append((a, n))

    matched = dict(seed)
    taken = set(matched.values())
    for a, cands in a_best.items():
        if a in matched or len(cands) != 1:
            continue
        bk, n = cands[0]
        if n < min_votes or len(b_best[bk]) != 1 or bk in taken:
            continue
        matched[a] = bk
        taken.add(bk)
    print(f"{A.label}->{B.label}: {len(matched)} after fingerprinting")

    for _ in range(30):
        b_matched = set(matched.values())
        votes = Counter()
        forced = Counter()
        for a_fn, b_fn in matched.items():
            for a_edges, b_edges in (
                (A.callees, B.callees),
                (A.callers, B.callers),
            ):
                a_nbrs = [x for x in a_edges.get(a_fn, ()) if x not in matched]
                b_nbrs = [x for x in b_edges.get(b_fn, ()) if x not in b_matched]
                if not a_nbrs or not b_nbrs:
                    continue
                if len(a_nbrs) == 1 and len(b_nbrs) == 1:
                    forced[(a_nbrs[0], b_nbrs[0])] += 1
                if len(a_nbrs) * len(b_nbrs) > 64:
                    continue
                for x in a_nbrs:
                    for y in b_nbrs:
                        votes[(x, y)] += 1
        cand_a = defaultdict(list)
        cand_b = defaultdict(list)
        for (x, y), n in votes.items():
            n += 10 * forced.get((x, y), 0)
            if n >= min_votes or (x, y) in forced:
                cand_a[x].append((n, y))
                cand_b[y].append((n, x))
        added = 0
        taken = set(matched.values())
        for x, cands in cand_a.items():
            if x in matched:
                continue
            cands.sort(reverse=True)
            n, y = cands[0]
            if (len(cands) > 1 and cands[1][0] == n) or y in taken:
                continue
            ycands = sorted(cand_b[y], reverse=True)
            if ycands[0][1] != x or (len(ycands) > 1 and ycands[1][0] == ycands[0][0]):
                continue
            matched[x] = y
            taken.add(y)
            added += 1
        if not added:
            break
    print(f"{A.label}->{B.label}: {len(matched)} after call-graph expansion")
    return matched


def load_targets(mangled_to_va):
    """Upstream's supported functions: upstream name -> 4.13 function VA."""
    targets = {}
    unmapped = []
    for entry in json.loads(TARGETS.read_text()):
        va = mangled_to_va.get(entry["mangled_name"])
        if va is None:
            unmapped.append(entry["name"])
        else:
            targets[entry["name"]] = va
    if unmapped:
        print(f"targets without a PDB entry ({len(unmapped)}): {', '.join(unmapped[:8])}...")
    return targets


def main():
    write = "--write" in sys.argv
    min_votes = 2
    chain = [b for b in DEFAULT_CHAIN if b in BUILDS]
    for i, a in enumerate(sys.argv):
        if a == "--min-votes":
            min_votes = int(sys.argv[i + 1])
        if a == "--builds":
            chain = sys.argv[i + 1].split(",")

    ref_side, ref_names, ref_mangled = load_side_413()
    targets = load_targets(ref_mangled)
    target_name_by_va = {va: name for name, va in targets.items()}
    print(f"upstream surface: {len(targets)} target functions")

    vas_by_name = defaultdict(list)
    for va, n in ref_names.items():
        vas_by_name[n].append(va)

    data = json.loads(OFFSETS.read_text())

    def curated_seed(build):
        seed = {}
        for name, entry in data["functions"].items():
            addr = entry.get(build) if isinstance(entry, dict) else None
            if not addr or not str(addr).startswith("0x") or name.startswith("_"):
                continue
            va = targets.get(name)
            if va is None and len(vas_by_name.get(name, ())) == 1:
                va = vas_by_name[name][0]
            if va is not None:
                seed[va] = int(addr, 16)
        return seed

    OUT.mkdir(exist_ok=True)
    prev_side = ref_side
    chain_map = {va: va for va in ref_names}  # 4.13 va -> prev_side key
    for build in chain:
        try:
            side = load_side_build(build)
        except Exception as e:
            print(f"{build}: SKIP ({e})")
            continue
        seed = {}
        curated = curated_seed(build)
        for ref_va, prev_key in chain_map.items():
            if ref_va in curated:
                seed[prev_key] = curated[ref_va]
        print(f"{build}: seeding with {len(seed)} curated matches")
        hop = match_sides(prev_side, side, seed, min_votes)
        # Compose: 4.13 va -> this build's address.
        chain_map = {
            ref_va: hop[prev_key]
            for ref_va, prev_key in chain_map.items()
            if prev_key in hop
        }
        print(f"{build}: {len(chain_map)} composed matches from 4.13")

        report = {}
        added = conflicts = on_surface = 0
        for ref_va, addr in sorted(chain_map.items(), key=lambda kv: ref_names.get(kv[0], "")):
            name = ref_names.get(ref_va)
            if name is None:
                continue
            target_name = target_name_by_va.get(ref_va)
            report[name] = {
                "address": f"0x{addr:X}",
                "upstream_surface": target_name is not None,
            }
            if target_name is None:
                continue
            on_surface += 1
            entry = data["functions"].setdefault(target_name, {})
            existing = entry.get(build)
            if existing and not str(existing).startswith("0x"):
                existing = None  # a NOT_YET_FOUND / NOT_IN_THIS_VERSION flag
            if existing and int(existing, 16) != addr:
                print(f"{build}: KEEPING curated {target_name} {existing} over matched 0x{addr:X}")
                conflicts += 1
                continue
            if not existing:
                added += 1
            entry[build] = f"0x{addr:X}"
        (OUT / f"propagated_{build}.json").write_text(json.dumps(report, indent=1) + "\n")
        print(
            f"{build}: {on_surface}/{len(targets)} upstream-surface functions matched, "
            f"+{added} new, {conflicts} kept-curated conflicts"
        )
        prev_side = side
    if write:
        OFFSETS.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {OFFSETS}")


if __name__ == "__main__":
    main()
