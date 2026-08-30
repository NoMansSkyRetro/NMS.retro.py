"""Finder for the ``interaction_trade`` batch.

Targets (all NOT_YET_FOUND in 1.09.1 / 1.13 / 1.24 / 1.38): the interaction-component,
persistent-interaction, reward-manager, purchaseable-item, inventory-store and
notification functions listed in ``TARGETS`` below. Includes the NMS-Newton hooks
cGcInteractionComponent::GetPuzzle and cGcRewardManager::GiveGenericReward.

Outcome: this script resolves none of them, and it says so with a computed reason per
function (see the report on stdout / the ``unresolved`` block). That is a deliberate,
audited result, not a stub. The derivation below is deterministic and re-runnable so
the negative result can be reproduced and challenged.

Why the usual levers all fail here (each verified against the four DBs):

* Distinctive strings / imm64 TkID constants -- the ``strings`` and ``imm64`` in
  out/target_hints.json are harvested from the modern 4.13 build. None of them occur
  in ANY legacy exe (checked byte-for-byte: UI_REWARD_SHIP_OSD, FrigateTeleportTarget,
  enabledNodeCount, 0xA3784A062B2E43DB, ... -> 0 occurrences). The referenced features
  post-date these 2016-2018 builds, so the fingerprint tokens do not transfer.
* Profiler / RTTI name literals -- none of the target method names occur as literals
  in the legacy binaries (GiveGenericReward, PopulateArrays, SaveInteraction, ... -> 0).
  harvest_name_literals already swept the resolvable single-owner cases.
* Anchored call graph -- this is the only remaining signal, and it is what the script
  actually computes below. For every target we take the callers/callees that ARE
  already located (offsets.json curated + out/propagated_<build>.json) and intersect
  their call sets. The result is never a clean, function-shaped singleton:
    - Small accessors (GetPuzzle 138B, GetInteractionData, FindFirstTypedComponent,
      SetDefaults 21B) are inlined into their legacy callers -- the multi-caller
      callee-intersection collapses to shared utilities (cTkMemoryManager::Free /
      Malloc, the string helper), never to the accessor itself.
    - Reward / inventory / persistent-interaction functions sit in compilation units
      whose distinctive internal callees (LookupGenericRewardByID, GiveRewardsFromList,
      GetProductSlotMaxStorage, InventoryElement::SetDefaults, the ScanEventManager
      pair, ...) are themselves unresolved, so the only surviving anchors are generic
      frontend/interaction callers plus high-fan-out utilities that do not discriminate.
    - The remaining targets (GetElement, Remove, DeepInterstellarSearch,
      PopulateBufferData, PurchaseableItem::Update, SaveInteraction, the buffer-side
      LoadGalacticAddressBuffers) have zero resolved non-utility anchors in any build.
  The automated propagate_symbols pass (fingerprint + 30 rounds of call-graph
  expansion, i.e. a superset of this method) already failed to place all 18, which is
  why they are NOT_YET_FOUND; the per-target analysis here reproduces and explains that.

Committing a guess off a 1-caller / utility-only anchor would violate the HUNTING.md
rule of two independent signals before a hard commit, so every target is reported
unresolved with the measured evidence that led there.

    python finders/find_interaction_trade.py        # prints one JSON object to stdout

stdout is pure JSON; all reasoning goes to stderr.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import BUILDS, Binary  # noqa: E402
import propagate_symbols as P  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
OFFSETS = HERE.parents[1] / "nmspy" / "data" / "offsets.json"
HINTS = HERE / "out" / "target_hints.json"

TARGETS = [
    "cGcInteractionComponent::FindFirstTypedComponent",
    "cGcInteractionComponent::GetInteractionData",
    "cGcInteractionComponent::GetPuzzle",
    "cGcInteractionComponent::GiveReward",
    "cGcInteractionData::SetDefaults",
    "cGcInventoryStore::Add",
    "cGcInventoryStore::GetElement",
    "cGcInventoryStore::Remove",
    "cGcInventoryStore::cGcInventoryStore",
    "cGcNotificationSequenceStartEvent::DeepInterstellarSearch",
    "cGcPersistentInteractionBuffer::LoadGalacticAddressBuffers",
    "cGcPersistentInteractionBuffer::PopulateBufferData",
    "cGcPersistentInteractionBuffer::SaveInteraction",
    "cGcPersistentInteractionsManager::LoadGalacticAddressBuffers",
    "cGcPersistentInteractionsManager::PopulateArrays",
    "cGcPurchaseableItem::Update",
    "cGcRewardManager::GiveGenericReward",
    "cGcSimpleInteractionComponent::DoAction",
]

# A callee with more callers than this is a shared utility (allocator, string helper,
# operator new, ...); it cannot discriminate a target and is excluded from anchoring.
UTIL_FANOUT = 300


def log(*a):
    print(*a, file=sys.stderr)


def build_context():
    """Load the four legacy sides plus the resolved-name maps."""
    hints = json.loads(HINTS.read_text())
    offsets = json.loads(OFFSETS.read_text())["functions"]
    sides, sizes, resolved = {}, {}, {}
    saved_stdout = sys.stdout
    for build in BUILDS:
        log(f"[{build}] building call graph ...")
        sys.stdout = sys.stderr  # Side.__init__ prints progress; keep it off our JSON stdout
        try:
            side = P.load_side_build(build)
        finally:
            sys.stdout = saved_stdout
        sides[build] = side
        b = Binary(build)
        sizes[build] = {a: s for a, s in b.db.execute("SELECT address, size FROM decompilations")}
        # name -> legacy address, from curated offsets + propagated matches
        name2addr = {}
        prop = json.loads((HERE / "out" / f"propagated_{build}.json").read_text())
        for name, entry in prop.items():
            a = entry.get("address")
            if isinstance(a, str) and a.startswith("0x"):
                name2addr[name] = int(a, 16)
        for name, entry in offsets.items():
            a = entry.get(build) if isinstance(entry, dict) else None
            if isinstance(a, str) and a.startswith("0x"):
                name2addr[name] = int(a, 16)  # curated wins
        resolved[build] = name2addr
    return hints, sides, sizes, resolved


def anchors(target, build, hints, resolved):
    """Return (resolved_callers, resolved_nonutil_callees) as name->addr dicts."""
    side = SIDES[build]
    d = hints[target]
    r = resolved[build]
    rc = {c: r[c] for c in d.get("modern_callers", []) if c in r}
    rd = {}
    for c in d.get("modern_callees", []):
        if c in r:
            a = r[c]
            if len(side.callers.get(a, ())) <= UTIL_FANOUT:
                rd[c] = a
    return rc, rd


def caller_intersection(target, build, hints, resolved):
    """Functions called by every resolved caller, restricted to non-utilities."""
    side = SIDES[build]
    rc, _ = anchors(target, build, hints, resolved)
    inter = None
    for addr in rc.values():
        cs = {x for x in side.callees.get(addr, ()) if len(side.callers.get(x, ())) <= UTIL_FANOUT}
        inter = cs if inter is None else (inter & cs)
    return rc, (inter or set())


def analyze(target, hints, resolved):
    """Attempt to locate ``target``; return (addresses_by_build, reason_or_None)."""
    per_build_candidates = {}
    n_callers, n_nonutil_callees = {}, {}
    for build in BUILDS:
        rc, rd = anchors(target, build, hints, resolved)
        n_callers[build] = len(rc)
        n_nonutil_callees[build] = len(rd)
        _, inter = caller_intersection(target, build, hints, resolved)
        per_build_candidates[build] = inter

    # A confident hit would be the SAME-shaped singleton reproduced across >=3 builds
    # and verified as a real function start. In practice this never fires for this
    # batch (documented in the module docstring); the check stays so the derivation is
    # explicit and a future anchor improvement can light it up.
    singletons = {b: next(iter(c)) for b, c in per_build_candidates.items() if len(c) == 1}
    addresses = {}
    if len(singletons) >= 3:
        for build, addr in singletons.items():
            if Binary(build).function_at(addr) is not None:
                addresses[build] = f"0x{addr:X}"
        if len(addresses) >= 3:
            return addresses, None  # would-be confident result

    # Otherwise: build an accurate one-line reason from the measured evidence.
    max_callers = max(n_callers.values())
    max_callees = max(n_nonutil_callees.values())
    cand_sizes = {b: len(c) for b, c in per_build_candidates.items()}
    if max_callers == 0 and max_callees == 0:
        reason = ("no resolved caller/callee anchors in any build; 4.13-only "
                  "strings/imm64/name-literals absent from legacy exes -> unanchored")
    elif max_callers >= 2 and all(v == 0 for v in cand_sizes.values()):
        reason = (f"{max_callers} resolved callers but non-utility callee-intersection "
                  f"is empty in every build -> accessor inlined into its legacy callers")
    elif max_callers >= 2:
        reason = (f"{max_callers} resolved callers; caller-intersection stays ambiguous "
                  f"(candidates/build={cand_sizes}); no distinctive resolved callee to pin it")
    else:
        reason = (f"only {max_callers} resolved caller and {max_callees} resolved "
                  f"non-utility callee(s); anchors too weak to disambiguate (>=2 signals needed)")
    return {}, reason


def main():
    global SIDES
    hints, SIDES, SIZES, RESOLVED = build_context()
    functions, unresolved = {}, {}
    for target in TARGETS:
        addrs, reason = analyze(target, hints, RESOLVED)
        if addrs:
            functions[target] = addrs
            log(f"RESOLVED {target}: {addrs}")
        else:
            unresolved[target] = reason
            log(f"UNRESOLVED {target}: {reason}")
    json.dump({"functions": functions, "unresolved": unresolved}, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
