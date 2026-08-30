"""Evaluate upstream NMS.py's modern byte signatures against the legacy exes.

Upstream locates functions with wildcarded byte patterns generated against the
modern (4.x) binary. This scans those patterns over a legacy exe's .text and reports
how many hit exactly once (usable), never (dead), or multiple times (ambiguous) —
quantifying how little of the modern signature set survives the compiler/code gap,
which is why propagate_symbols.py fingerprints strings instead.

The signature list is upstream's tools/data.json, recoverable from git history:
    git show <pre-retarget-commit>:tools/data.json > data_413.json

    python try_modern_signatures.py 1.13 path/to/data_413.json
"""

import json
import re
import sys

from common import Binary


def pattern_to_regex(sig: str) -> re.Pattern:
    parts = []
    for tok in sig.split():
        parts.append(b"." if tok == "?" else re.escape(bytes([int(tok, 16)])))
    return re.compile(b"".join(parts), re.DOTALL)


def main():
    build, data_path = sys.argv[1], sys.argv[2]
    b = Binary(build)
    text_sec = next(s for s in b.sections if s.name == ".text")
    text = b.data[text_sec.raw_offset : text_sec.raw_offset + text_sec.raw_size]
    entries = json.load(open(data_path))
    unique = dead = multi = 0
    for e in entries:
        hits = [m.start() for m in pattern_to_regex(e["signature"]).finditer(text)]
        if len(hits) == 1:
            unique += 1
            va = 0x140000000 + text_sec.virtual_address + hits[0]
            row = b.function_at(va)
            note = "" if row else "  (NOT a function start!)"
            print(f"  UNIQUE {e['name']} @ 0x{va:X}{note}")
        elif not hits:
            dead += 1
        else:
            multi += 1
    print(f"{build}: {len(entries)} signatures -> {unique} unique, {multi} ambiguous, {dead} no match")


if __name__ == "__main__":
    main()
