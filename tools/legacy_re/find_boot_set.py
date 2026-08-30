"""Locate the boot-set functions and globals in one build, automatically.

Automates the identification chain documented in findings.md:

    cTkFSMState::StateChange  smallest function containing the "FSM IGNORED" string
    cTkFSM::Construct         the next function after it (same compilation unit)
    cGcApplication::Construct the one external caller of cTkFSM::Construct
    cGcApplication (global)   first argument of the cTkFSM::Construct call there
    cGcApplicationData*       the alloc-result global assigned in the same function
    app static ctor           the function stamping the vtable onto the app global
    cTkFSM::Update            vtable slot 2 (slot 1 must equal cTkFSM::Construct)
    cGcApplication::Update    the one external caller of cTkFSM::Update
    cTkFSM::StateChange       called from cTkFSM::Update with (this, this+0x18, ...)

Prints the result and, with --write, merges it into nmspy/data/offsets.json.
Every step asserts, so a build whose code shape differs fails loudly rather than
producing silently-wrong addresses.

    python find_boot_set.py 1.09.1 [--write]
"""

import json
import re
import sys
from pathlib import Path

from common import Binary

OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"


def one_external_caller(b: Binary, address: int) -> int:
    callers = [
        (name, addr)
        for name, addr, _ in b.functions_matching(f"%FUN_{address:x}%")
        if addr != address
    ]
    assert len(callers) == 1, f"expected 1 caller of 0x{address:X}, got {callers}"
    return callers[0][1]


def find(build: str) -> dict:
    b = Binary(build)
    out = {}

    # cTkFSMState::StateChange: smallest FSM IGNORED function.
    hits = b.db.execute(
        "SELECT address, size FROM decompilations WHERE raw_decomp LIKE '%FSM IGNORED%' "
        "ORDER BY size LIMIT 1"
    ).fetchone()
    assert hits and hits[1] < 100, f"no small FSM IGNORED function: {hits}"
    out["cTkFSMState::StateChange"] = hits[0]

    # cTkFSM::Construct: next function in address order, ~274 bytes.
    nxt = b.db.execute(
        "SELECT address, size FROM decompilations WHERE address > ? ORDER BY address LIMIT 1",
        (hits[0],),
    ).fetchone()
    assert nxt and 200 < nxt[1] < 400, f"unexpected cTkFSM::Construct candidate: {nxt}"
    out["cTkFSM::Construct"] = nxt[0]

    # cGcApplication::Construct and the two globals.
    boot = one_external_caller(b, nxt[0])
    out["cGcApplication::Construct"] = boot
    decomp = b.function_at(boot)[3]
    m = re.search(rf"FUN_{nxt[0]:x}\(&DAT_(14[0-9a-f]+),", decomp)
    assert m, "cTkFSM::Construct call with app global not found"
    app_global = int(m.group(1), 16)
    out["global cGcApplication"] = app_global
    m = re.search(r"DAT_(14[0-9a-f]+) = FUN_14[0-9a-f]+\([^)]*0x[0-9a-f]{6},0x10,", decomp)
    assert m, "application data alloc not found"
    out["global cGcApplicationData*"] = int(m.group(1), 16)

    # Static ctor -> vtable -> cTkFSM::Update.
    rows = b.functions_matching(f"%_DAT_{app_global:x} = &PTR_%")
    assert len(rows) == 1, f"expected 1 static ctor, got {rows}"
    ctor_decomp = b.function_at(rows[0][1])[3]
    m = re.search(rf"_DAT_{app_global:x} = &PTR_\w+_(14[0-9a-f]+);", ctor_decomp)
    assert m, "vtable assignment not found"
    vtable = int(m.group(1), 16)
    assert b.read_ptr(vtable + 8) == nxt[0], "vtable slot 1 is not cTkFSM::Construct"
    fsm_update = b.read_ptr(vtable + 16)
    assert b.function_at(fsm_update), "vtable slot 2 is not a function"
    out["cTkFSM::Update"] = fsm_update

    # cGcApplication::Update and cTkFSM::StateChange.
    out["cGcApplication::Update"] = one_external_caller(b, fsm_update)
    update_decomp = b.function_at(fsm_update)[3]
    m = re.search(r"FUN_(14[0-9a-f]+)\(param_1,param_1 \+ 0x18", update_decomp)
    assert m, "cTkFSM::StateChange call not found in cTkFSM::Update"
    out["cTkFSM::StateChange"] = int(m.group(1), 16)

    return out


def main():
    build = sys.argv[1]
    write = "--write" in sys.argv
    found = find(build)
    for name, addr in found.items():
        print(f"{name}: 0x{addr:X}")

    data = json.loads(OFFSETS.read_text())
    mismatches = []
    for name, addr in found.items():
        table = data["globals"] if name.startswith("global ") else data["functions"]
        key = name.removeprefix("global ")
        existing = table.setdefault(key, {}).get(build)
        if existing and not str(existing).startswith("0x"):
            existing = None  # a NOT_YET_FOUND / NOT_IN_THIS_VERSION flag
        if existing and int(existing, 16) != addr:
            mismatches.append(f"{key}: json has {existing}, found 0x{addr:X}")
        table[key][build] = f"0x{addr:X}"
    if mismatches:
        sys.exit("MISMATCH with existing offsets.json:\n" + "\n".join(mismatches))
    print("consistent with existing offsets.json")
    if write:
        OFFSETS.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {OFFSETS}")


if __name__ == "__main__":
    main()
