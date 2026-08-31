"""Backfill partially-mapped functions by cross-version porting.

A "partial" is a surface function already located in at least one build but still
NOT_YET_FOUND in another. handles.Xverse.port() is high precision (it returns a build
only when the distinctive-token winner and the call-graph winner agree, or one is
overwhelming), so porting a partial from each build where it IS known, and accepting a
missing slot only when every source that resolves it agrees on the same address, is a
safe automated backfill. merge_finder_results.py re-validates each address as a real
function start before it lands.

Deterministic and self-contained: re-running reproduces the same addresses.

    python finders/find_ports.py            # prints the merge JSON contract to stdout
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from handles import Xverse  # noqa: E402

VERSIONS = ["1.09.1", "1.13", "1.24", "1.38"]
OFFSETS = Path(__file__).resolve().parents[3] / "nmspy" / "data" / "offsets.json"


def is_addr(v):
    return isinstance(v, str) and v.startswith("0x")


def main():
    functions = json.loads(OFFSETS.read_text())["functions"]
    partials = {
        n: e for n, e in functions.items()
        if any(is_addr(e.get(v)) for v in VERSIONS) and any(e.get(v) == "NOT_YET_FOUND" for v in VERSIONS)
    }
    print(f"[find_ports] {len(partials)} partials", file=sys.stderr)

    xv = Xverse(verbose=True)
    out_funcs, unresolved = {}, {}
    for name, e in partials.items():
        known = {v: int(e[v], 16) for v in VERSIONS if is_addr(e.get(v))}
        missing = [v for v in VERSIONS if e.get(v) == "NOT_YET_FOUND"]
        votes = {m: {} for m in missing}   # build -> {addr: [source builds]}
        for src, va in known.items():
            ported = xv.port(src, va)
            for m in missing:
                if m in ported:
                    votes[m].setdefault(ported[m], []).append(src)
        resolved = {}
        for m in missing:
            addrs = list(votes[m])
            if len(addrs) == 1 and xv.is_func(m, addrs[0]):
                resolved[m] = f"0x{addrs[0]:X}"
            elif len(addrs) > 1:
                print(f"[find_ports] CONFLICT {name} {m}: "
                      f"{ {f'0x{a:X}': votes[m][a] for a in addrs} }", file=sys.stderr)
        if resolved:
            out_funcs[name] = resolved
            print(f"[find_ports] {name}: {resolved}", file=sys.stderr)
        else:
            unresolved[name] = f"port() abstained for {missing} (no agreeing distinctive-token/call-graph winner)"

    print(json.dumps({"functions": out_funcs, "unresolved": unresolved}))


if __name__ == "__main__":
    main()
