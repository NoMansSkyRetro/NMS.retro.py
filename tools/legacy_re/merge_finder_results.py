"""Run every finder script in finders/ and merge validated results into offsets.json.

Each ``finders/*.py`` is a self-contained, re-runnable derivation (written during the
NOT_YET_FOUND hunt) that prints a JSON object to stdout:

    {"functions": {"cGcX::Y": {"1.13": "0x1401234A0", ...}, ...},
     "unresolved": {"cGcX::Z": "why it could not be located", ...}}

This tool executes each script, then accepts an address only when:

- the name is part of the upstream surface,
- the address is a recorded function start in that build's decompilation DB,
- the current offsets.json slot is NOT_YET_FOUND (an existing address must agree;
  a disagreement is reported and the curated value kept).

    python merge_finder_results.py [--write] [finders ...]
"""

import json
import subprocess
import sys
from pathlib import Path

from common import BUILDS, Binary

HERE = Path(__file__).parent
OFFSETS = HERE.parents[1] / "nmspy" / "data" / "offsets.json"
VERSIONS = list(BUILDS)


def main():
    write = "--write" in sys.argv
    picked = [a for a in sys.argv[1:] if not a.startswith("--")]
    scripts = [Path(p) for p in picked] if picked else sorted((HERE / "finders").glob("*.py"))

    data = json.loads(OFFSETS.read_text())
    functions = data["functions"]
    dbs = {}

    def db(build):
        if build not in dbs:
            dbs[build] = Binary(build)
        return dbs[build]

    total_added = total_bad = 0
    for script in scripts:
        proc = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, cwd=HERE
        )
        if proc.returncode != 0:
            print(f"{script.name}: FAILED\n{proc.stderr.strip()[-800:]}")
            total_bad += 1
            continue
        try:
            payload = json.loads(proc.stdout[proc.stdout.index("{"):])
        except Exception as e:
            print(f"{script.name}: bad output ({e})")
            total_bad += 1
            continue
        added = rejected = 0
        for name, per_version in payload.get("functions", {}).items():
            entry = functions.get(name)
            if entry is None:
                print(f"{script.name}: SKIP unknown function {name}")
                continue
            for build, address in per_version.items():
                if build not in VERSIONS or not str(address).startswith("0x"):
                    continue
                addr = int(address, 16)
                if db(build).function_at(addr) is None:
                    print(f"{script.name}: REJECT {name} {build} {address}: not a function start")
                    rejected += 1
                    continue
                existing = entry.get(build)
                if str(existing).startswith("0x"):
                    if int(existing, 16) != addr:
                        print(f"{script.name}: CONFLICT {name} {build}: keeping {existing} over {address}")
                        rejected += 1
                    continue
                entry[build] = f"0x{addr:X}"
                added += 1
        for name, reason in payload.get("unresolved", {}).items():
            entry = functions.get(name)
            if entry is not None and reason and "_unresolved" not in entry:
                entry["_unresolved"] = reason
        print(f"{script.name}: +{added} addresses, {rejected} rejected")
        total_added += added

    print(f"total: +{total_added} addresses from {len(scripts)} finders")
    if write:
        OFFSETS.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {OFFSETS}")


if __name__ == "__main__":
    main()
