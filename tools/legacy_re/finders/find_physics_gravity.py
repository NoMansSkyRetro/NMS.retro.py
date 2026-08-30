#!/usr/bin/env python3
"""Finder for the ``physics_gravity`` batch.

Targets (cTkDynamicGravityControl / cTkRigidBody / cGcDestructableComponent):

    cTkDynamicGravityControl::cTkDynamicGravityControl   (ctor)
    cTkDynamicGravityControl::Construct
    cTkDynamicGravityControl::GetGravity
    cTkDynamicGravityControl::UpdateGravityPoint
    cGcDestructableComponent::Destroy
    cTkRigidBody::SetAngularVelocity
    cTkRigidBody::SetLinearVelocity

None of these carry distinctive strings or imm64 TkID constants (that is why the
4.13->legacy fingerprint propagation left them NOT_YET_FOUND), so the usual
string / imm64 anchors do not apply. The one member that has an *invariant code
fingerprint* across builds is the constructor.

Constructor fingerprint
-----------------------
cTkDynamicGravityControl holds a fixed 64-entry free list of gravity OBB slots.
Both the modern ctor and the modern Construct() initialise it with the same loop
(verified by disassembling the 4.13 build)::

    lea  rdx, [this + <base>]
  L:  movsx r, ax/cx
      mov  [rdx + 0x100], r          ; parallel index array  -> 89 8x 00 01 00 00
      mov  dword [rdx], 0xffffffff    ; free-list sentinel     -> C7 0x FF FF FF FF
      inc  ax/cx
      lea  rdx, [rdx + 4]
      cmp  ax/cx, 0x40
      jl   L

In 1.09.1 and 1.13 the ctor is a ~117-byte function that ends with this loop and
returns ``this``. It is reached from a single owning-object constructor whose
prologue is itself distinctive::

    xor  esi, esi
    mov  [rcx], rsi ; mov [rcx+8], rsi ; mov [rcx+0x10], rsi ; mov byte [rcx+0x18], sil
    add  rcx, 0x120
    call <member ctor>
    ... stores 0x3ffff three times ...
    call <cTkDynamicGravityControl::cTkDynamicGravityControl>   <-- the target

We locate that owning ctor by its prologue bytes, then pick the callee that is a
function start carrying the free-list sentinel loop. Two independent signals agree
(the sentinel loop *and* the owning-ctor call site), so the match is a lock.

In 1.24 and 1.38 the gravity control was refactored: the 64-slot / 0xffffffff
free-list loop no longer exists, the owning-ctor prologue is gone, and the 4.13
modern call graph for the ctor is polluted by identical-COMDAT-folding (~298
folded callers), so neither the code fingerprint nor an anchored call-graph vote
resolves those two builds. They are reported unresolved rather than guessed.

Run from tools/legacy_re/:  python finders/find_physics_gravity.py
Emits one JSON object on stdout; reasoning goes to stderr.
"""

import json
import os
import re
import sys
from bisect import bisect_right

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import Binary  # noqa: E402

BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]

# owning-ctor prologue: xor esi,esi ; mov [rcx],rsi ; mov [rcx+8],rsi ;
# mov [rcx+0x10],rsi ; mov byte [rcx+0x18],sil
OWNER_PROLOGUE = bytes.fromhex("33F6488931488971084889711040887118")
SENTINEL = re.compile(rb"\xc7[\x00-\x47]\xff\xff\xff\xff")           # mov dword[reg], 0xffffffff
INDEX_STORE = re.compile(rb"\x89[\x80-\xbf]\x00\x01\x00\x00")         # mov [reg+0x100], r32


def log(*a):
    print(*a, file=sys.stderr)


class Fn:
    def __init__(self, b):
        self.b = b
        rows = b.db.execute("SELECT address, size FROM decompilations").fetchall()
        self.size = {a: s for a, s in rows}
        self.starts = sorted(self.size)

    def containing(self, va):
        i = bisect_right(self.starts, va) - 1
        if i >= 0:
            s = self.starts[i]
            if s <= va < s + (self.size.get(s, 0) or 0x8000):
                return s
        return None

    def is_start(self, va):
        return va in self.size

    def code(self, va):
        off = self.b.va_to_file_offset(va)
        if off is None:
            return b""
        return self.b.data[off:off + (self.size.get(va, 0) or 0)]

    def ordered_callees(self, va):
        """Direct E8 call targets of function `va`, in address order."""
        off = self.b.va_to_file_offset(va)
        sz = self.size.get(va, 0) or 0
        out = []
        p = off
        while p is not None and p < off + sz - 4:
            if self.b.data[p] == 0xE8:
                rel = int.from_bytes(self.b.data[p + 1:p + 5], "little", signed=True)
                src = self.b.file_offset_to_va(p)
                if src is not None:
                    out.append(src + 5 + rel)
                p += 5
            else:
                p += 1
        return out


def find_gravity_ctor(build):
    """Return the VA of cTkDynamicGravityControl::cTkDynamicGravityControl, or None."""
    b = Binary(build)
    fn = Fn(b)

    # 1) locate the owning-object ctor(s) by prologue bytes
    owners = []
    for m in re.finditer(re.escape(OWNER_PROLOGUE), b.data):
        va = b.file_offset_to_va(m.start())
        if va is None:
            continue
        owner = fn.containing(va)
        if owner is not None:
            owners.append(owner)
    owners = sorted(set(owners))
    log(f"[{build}] owning-ctor prologue matches: {[hex(o) for o in owners]}")

    # 2) among an owner's callees, the gravity ctor is the small function that
    #    both stores the free-list sentinel and the parallel index array.
    hits = []
    for owner in owners:
        for callee in fn.ordered_callees(owner):
            if not fn.is_start(callee):
                continue
            sz = fn.size.get(callee, 0)
            if not (80 <= sz <= 220):
                continue
            code = fn.code(callee)
            if SENTINEL.search(code) and INDEX_STORE.search(code):
                hits.append(callee)
    hits = sorted(set(hits))
    if len(hits) == 1:
        log(f"[{build}] gravity ctor = 0x{hits[0]:X} (sentinel loop + owning-ctor call site)")
        return hits[0]
    if not hits:
        log(f"[{build}] no sentinel-loop callee under an owning ctor -> refactored/absent")
    else:
        log(f"[{build}] ambiguous sentinel-loop callees {[hex(h) for h in hits]} -> not committing")
    return None


UNRESOLVED_REASONS = {
    "cTkDynamicGravityControl::Construct":
        "void()->void reset that shares the ctor's 64-slot init loop; in 1.09.1/1.13 "
        "it is inlined (no standalone loop-bearing sibling under BootState::Update or "
        "the owning ctor); in 1.24/1.38 the free-list loop is refactored away. No "
        "second independent signal, so left unresolved.",
    "cTkDynamicGravityControl::GetGravity":
        "leaf-ish const method (only callee cTkAABB::IsPositionInBox, itself unmapped); "
        "no strings/imm64; modern caller set is a folded/subset of the ctor's and the "
        "legacy caller-intersection is dominated by generic helpers (memcpy/vector ops), "
        "so no unique legacy VA stands out.",
    "cTkDynamicGravityControl::UpdateGravityPoint":
        "single modern caller cGcPlanet::UpdateGravity, which is itself NOT_YET_FOUND, "
        "so there is no mapped anchor; no strings/imm64 and no distinctive standalone loop.",
    "cGcDestructableComponent::Destroy":
        "large (11.6 KB) function; none of its 9 modern callers are present in the seed "
        "(offsets.json + propagated_*.json), so the anchored caller vote has zero support "
        "and the referenced strings ('Not Found', a creature-perception source path) are "
        "shared by many functions.",
    "cTkRigidBody::SetAngularVelocity":
        "89-byte leaf in tkrigidbody.cpp/havok; sets velocity via the stored Havok body "
        "(indirect, 0 direct callees) so no callee fingerprint; only 1-2 of its 21 modern "
        "callers map into the seed and they share only generic helpers -> no unique hit.",
    "cTkRigidBody::SetLinearVelocity":
        "identical situation to SetAngularVelocity (89-byte leaf, indirect Havok write); "
        "3-4 of 51 modern callers map but the shared legacy callees are generic helpers, "
        "not the target, so no address is committable.",
}


def main():
    functions = {}
    unresolved = {}

    ctor_name = "cTkDynamicGravityControl::cTkDynamicGravityControl"
    ctor_slots = {}
    for build in BUILDS:
        try:
            va = find_gravity_ctor(build)
        except Exception as e:  # pragma: no cover - defensive
            log(f"[{build}] error: {e}")
            va = None
        if va is not None:
            # sanity: must be a real function start in the DB
            b = Binary(build)
            if b.function_at(va):
                ctor_slots[build] = f"0x{va:X}"
            else:
                log(f"[{build}] 0x{va:X} is not a DB function start; dropping")
    if ctor_slots:
        functions[ctor_name] = ctor_slots
    else:
        unresolved[ctor_name] = "no build resolved"
    if ctor_name in functions and len(ctor_slots) < len(BUILDS):
        missing = [b for b in BUILDS if b not in ctor_slots]
        log(f"[ctor] resolved {sorted(ctor_slots)}, unresolved builds {missing} "
            f"(gravity control refactored: 64-slot free-list loop absent)")

    for name, reason in UNRESOLVED_REASONS.items():
        unresolved[name] = reason

    print(json.dumps({"functions": functions, "unresolved": unresolved}))


if __name__ == "__main__":
    main()
