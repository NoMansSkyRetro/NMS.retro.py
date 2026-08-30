"""Propagate the functions NMS.py supported on 4.13 to the legacy builds.

The goal is coverage of upstream NMS.py's own hook surface — the 331 functions in its
tools/data.json (bundled here as ``upstream_data_413.json``) — not the whole PDB.
Modern byte signatures do not survive six years of compiler and code drift (see
try_modern_signatures.py for the numbers), but string literals do. This tool:

1. Extracts every NUL-terminated ASCII string from a binary.
2. Finds every rel32 reference from code to one of those strings (numpy scan of every
   4-byte window in .text) and buckets the references by containing function; the
   4.13 side gets function bounds from the PDB dump (`reference_symbol_db.json`), the
   legacy side from the Ghidra decompilation database.
3. Calls a string *distinctive* when exactly one function references it (per side),
   and matches a legacy function to a 4.13 function when they share distinctive
   strings, the pairing is unique in both directions, and it has at least
   ``--min-votes`` shared distinctive strings (default 2; 1 recovers more names with
   slightly more risk).
4. Merges matched **upstream-surface** functions into nmspy/data/offsets.json under
   upstream's names, and writes every unambiguous match (surface or not) to
   ``out/propagated_<build>.json`` for reference. A conflict with an existing
   offsets.json entry aborts the merge — existing entries are ground truth.

    python propagate_symbols.py 1.13 1.24 1.38 [--write] [--min-votes N]
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


def fingerprint(data, sections, functions):
    """functions: sorted list of (start_va, size, key). Returns key -> set(tokens).

    Tokens are referenced string texts plus ("imm", value) for imm64 constants.
    """
    strings = extract_strings(data, sections)
    starts = [f[0] for f in functions]
    prints = defaultdict(set)
    text_off_to_va = {}
    for name, va, vsize, raw, rsize in sections:
        if name == ".text":
            text_off_to_va = (raw, STATIC_BASE + va)

    def add_token(off, token):
        ref_va = text_off_to_va[1] + (off - text_off_to_va[0])
        i = bisect_right(starts, ref_va) - 1
        if i >= 0:
            start, size, key = functions[i]
            if start <= ref_va < start + size:
                prints[key].add(token)

    for off, target in string_refs(data, sections, strings.keys()):
        add_token(off, strings[target])
    for off, imm in imm64_refs(data, sections):
        add_token(off, ("imm", imm))
    return prints


def call_edges(data, sections, functions):
    """caller/callee sets via E8/E9 rel32 whose target is a known function start.

    functions: sorted list of (start_va, size, key).
    """
    starts = [f[0] for f in functions]
    starts_arr = np.array(starts, dtype=np.int64)
    callees = defaultdict(set)
    callers = defaultdict(set)
    for name, va, vsize, raw, rsize in sections:
        if name != ".text":
            continue
        text = np.frombuffer(data, dtype=np.uint8, count=rsize, offset=raw)
        is_call = (text[:-5] == 0xE8) | (text[:-5] == 0xE9)
        pos = np.nonzero(is_call)[0]
        b = text
        i32 = (
            b[pos + 1].astype(np.uint32)
            | (b[pos + 2].astype(np.uint32) << 8)
            | (b[pos + 3].astype(np.uint32) << 16)
            | (b[pos + 4].astype(np.uint32) << 24)
        ).astype(np.int32)
        pos_va = STATIC_BASE + va + pos.astype(np.int64)
        targets = pos_va + 5 + i32
        idx = np.searchsorted(starts_arr, targets)
        hit = (idx < len(starts_arr)) & (starts_arr[np.minimum(idx, len(starts_arr) - 1)] == targets)
        for p, t in zip(pos[hit], targets[hit]):
            src_va = STATIC_BASE + va + int(p)
            i = bisect_right(starts, src_va) - 1
            if i < 0:
                continue
            start, size, key = functions[i]
            if start <= src_va < start + size:
                callees[key].add(int(t))
                callers[int(t)].add(key)
    return callees, callers


def callgraph_expand(matched, ref_graph, leg_graph, min_votes=2, max_rounds=20):
    """Grow ref->leg matches: vote for pairs co-occurring as callees (or callers) of
    already-matched pairs; accept mutually-unique best pairs with enough votes."""
    ref_callees, ref_callers = ref_graph
    leg_callees, leg_callers = leg_graph
    for _ in range(max_rounds):
        leg_matched = set(matched.values())
        votes = Counter()
        for ref_fn, leg_fn in matched.items():
            for ref_edges, leg_edges in (
                (ref_callees, leg_callees),
                (ref_callers, leg_callers),
            ):
                ref_nbrs = [r for r in ref_edges.get(ref_fn, ()) if r not in matched]
                leg_nbrs = [l for l in leg_edges.get(leg_fn, ()) if l not in leg_matched]
                # Only vote where the neighbourhood is small enough to be meaningful.
                if not ref_nbrs or not leg_nbrs or len(ref_nbrs) * len(leg_nbrs) > 64:
                    continue
                for r in ref_nbrs:
                    for l in leg_nbrs:
                        votes[(r, l)] += 1
        best_for_ref = defaultdict(list)
        best_for_leg = defaultdict(list)
        for (r, l), n in votes.items():
            if n >= min_votes:
                best_for_ref[r].append((n, l))
                best_for_leg[l].append((n, r))
        new = {}
        for r, cands in best_for_ref.items():
            cands.sort(reverse=True)
            n, l = cands[0]
            if len(cands) > 1 and cands[1][0] == n:
                continue
            lcands = sorted(best_for_leg[l], reverse=True)
            if lcands[0][1] != r or (len(lcands) > 1 and lcands[1][0] == lcands[0][0]):
                continue
            new[r] = l
        added = 0
        leg_taken = set(matched.values())
        for r, l in new.items():
            if r not in matched and l not in leg_taken:
                matched[r] = l
                leg_taken.add(l)
                added += 1
        if not added:
            break
    return matched


def distinctive(prints):
    counts = Counter()
    for texts in prints.values():
        counts.update(texts)
    return {t for t, n in counts.items() if n == 1}


def load_reference():
    data = open(EXE_413, "rb").read()
    sections = parse_sections(data)
    ref = json.load(open(REF_413))
    funcs = []
    names = {}
    mangled = {}
    for f in ref["functions"]:
        va = STATIC_BASE + f["rva"]
        funcs.append((va, f.get("length") or 0x10000, va))
        names[va] = f.get("undecorated_name") or f["name"]
        mangled[f["name"]] = va
    funcs.sort()
    print(f"4.13: {len(funcs)} functions; fingerprinting...")
    prints = fingerprint(data, sections, funcs)
    print(f"4.13: {len(prints)} functions reference strings")
    graph = call_edges(data, sections, funcs)
    print(f"4.13: call graph over {len(graph[0])} callers")
    return prints, names, mangled, graph


def match_build(build, ref_prints, ref_names, ref_graph, seed, min_votes):
    b = Binary(build)
    funcs = sorted(
        (addr, size, addr)
        for addr, size in b.db.execute("SELECT address, size FROM decompilations")
    )
    sections = [
        (s.name, s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size)
        for s in b.sections
    ]
    print(f"{build}: fingerprinting {len(funcs)} functions...")
    leg_prints = fingerprint(b.data, sections, funcs)

    ref_distinct = distinctive(ref_prints)
    leg_distinct = distinctive(leg_prints)
    shared = ref_distinct & leg_distinct

    ref_by_text = {}
    for key, texts in ref_prints.items():
        for t in texts & shared:
            ref_by_text[t] = key
    votes = Counter()
    for key, texts in leg_prints.items():
        for t in texts & shared:
            votes[(key, ref_by_text[t])] += 1

    leg_best = defaultdict(list)
    ref_best = defaultdict(list)
    for (leg, ref), n in votes.items():
        leg_best[leg].append((ref, n))
        ref_best[ref].append((leg, n))

    matched = dict(seed)  # ref_va -> leg_va (curated ground truth)
    fp_votes = {}
    for leg, cands in leg_best.items():
        if len(cands) != 1:
            continue
        ref, n = cands[0]
        if n < min_votes or len(ref_best[ref]) != 1:
            continue
        if ref not in matched and leg not in set(matched.values()):
            matched[ref] = leg
            fp_votes[ref] = n
    print(f"{build}: {len(matched)} matches after fingerprinting (min_votes={min_votes})")

    leg_graph = call_edges(b.data, sections, funcs)
    matched = callgraph_expand(matched, ref_graph, leg_graph, min_votes=min_votes)
    print(f"{build}: {len(matched)} matches after call-graph expansion")
    return {
        ref_names[ref]: (leg, fp_votes.get(ref, 0), ref)
        for ref, leg in matched.items()
        if ref in ref_names
    }


def load_targets(ref_names_by_mangled):
    """Upstream's 331 supported functions: upstream name -> 4.13 function VA."""
    targets = {}
    unmapped = []
    for entry in json.loads(TARGETS.read_text()):
        va = ref_names_by_mangled.get(entry["mangled_name"])
        if va is None:
            unmapped.append(entry["name"])
        else:
            targets[entry["name"]] = va
    if unmapped:
        print(f"targets without a PDB entry ({len(unmapped)}): {', '.join(unmapped[:8])}...")
    return targets


def main():
    builds = [a for a in sys.argv[1:] if not a.startswith("--")]
    write = "--write" in sys.argv
    min_votes = 2
    for i, a in enumerate(sys.argv):
        if a == "--min-votes":
            min_votes = int(sys.argv[i + 1])
            builds.remove(sys.argv[i + 1])

    ref_prints, ref_names, ref_mangled, ref_graph = load_reference()
    targets = load_targets(ref_mangled)
    target_name_by_va = {va: name for name, va in targets.items()}
    print(f"upstream surface: {len(targets)} target functions")

    # Reverse name lookup for seeding from curated entries (skip overloaded names).
    vas_by_name = defaultdict(list)
    for va, n in ref_names.items():
        vas_by_name[n].append(va)

    data = json.loads(OFFSETS.read_text())
    OUT.mkdir(exist_ok=True)
    for build in builds:
        seed = {}
        for name, entry in data["functions"].items():
            addr = entry.get(build)
            if not addr:
                continue
            va = targets.get(name)
            if va is None and len(vas_by_name.get(name, ())) == 1:
                va = vas_by_name[name][0]
            if va is not None:
                seed[va] = int(addr, 16)
        print(f"{build}: seeding with {len(seed)} curated matches")
        matched = match_build(build, ref_prints, ref_names, ref_graph, seed, min_votes)
        report = {}
        added = conflicts = on_surface = 0
        for name, (addr, votes_n, ref_va) in sorted(matched.items()):
            target_name = target_name_by_va.get(ref_va)
            report[name] = {
                "address": f"0x{addr:X}",
                "votes": votes_n,
                "method": "fingerprint" if votes_n else "callgraph",
                "upstream_surface": target_name is not None,
            }
            if target_name is None:
                continue
            on_surface += 1
            entry = data["functions"].setdefault(target_name, {})
            existing = entry.get(build)
            if existing and int(existing, 16) != addr:
                # Curated entries win; the fingerprint often lands on a helper the
                # distinctive strings moved into (e.g. a path-building lambda).
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
    if write:
        OFFSETS.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {OFFSETS}")


if __name__ == "__main__":
    main()
