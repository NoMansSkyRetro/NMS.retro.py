"""Ensure every upstream-supported function appears in offsets.json, flagged.

Every entry in upstream NMS.py's hook surface (upstream_data_413.json) gets a row in
nmspy/data/offsets.json with one value per build:

- an address ("0x...") when the function has been located;
- "NOT_IN_THIS_VERSION" when the feature verifiably postdates the build (rule table
  below, based on release history plus string probes of the legacy exes);
- "NOT_YET_FOUND" otherwise (it should exist, nobody has located it yet).

Rules carry a "_note" explaining the history. Existing addresses are never touched.

    python build_full_surface.py [--write]
"""

import json
import sys
from pathlib import Path

TARGETS = Path(__file__).parent / "upstream_data_413.json"
OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"

VERSIONS = ["1.09.1", "1.13", "1.24", "1.38"]
NOT_IN = "NOT_IN_THIS_VERSION"
NOT_FOUND = "NOT_YET_FOUND"

# (name prefix, first build that has the feature or None for none of them, note)
# Evidence: release history, cross-checked with string probes of the four exes
# (e.g. no NanoVG shader uniforms or TextChat strings exist in any 1.x binary).
RULES = [
    # nvg*: originally flagged NOT_IN_THIS_VERSION on one absent string, but the fleet
    # located cGcGalaxyMap::Data::RenderNVG in all four builds, so NanoVG-style drawing
    # is present. Downgraded to NOT_YET_FOUND (unlocated, possibly inlined) since we no
    # longer have positive evidence the primitives are absent.
    ("cGcTextChat", None, "Text chat arrived with multiplayer in NEXT (1.5); no TextChat strings in any 1.x exe."),
    ("cGcPlayerFleetManager", None, "Frigates and fleets arrived in NEXT (1.5)."),
    ("cGcPlayerCreatureOwnership", None, "Creature adoption arrived in Companions (3.2)."),
    ("cGcPlayerMultitoolOwnership", None, "Multiple multi-tool ownership arrived in NEXT (1.5)."),
    ("cGcFish", None, "Fishing arrived in Aquarius (5.1)."),
    ("cGcLocalPlayerCharacterInterface", None, "The third-person player character arrived in NEXT (1.5)."),
    ("cGcFrontendPagePortalRunes", "1.38", "Portal travel arrived in Atlas Rises (1.3)."),
    ("cGcTerrainEditorBeam", "1.38", "The terrain manipulator arrived in Atlas Rises (1.3)."),
    ("cGcPhotoModeUI", "1.24", "Photo mode arrived in Path Finder (1.2)."),
    ("cGcQuickMenu", "1.13", "Quick-menu strings first appear in Foundation (1.1)."),
    ("cGcBaseBuildingManager", "1.13", "Base building arrived in Foundation (1.1)."),
    ("cGcBaseSearch", "1.13", "Base building arrived in Foundation (1.1)."),
    ("cGcPlayerBasePersistentBuffer", "1.13", "Base building arrived in Foundation (1.1)."),
    ("cGcPlayerVehicleOwnership", "1.24", "Exocraft arrived in Path Finder (1.2)."),
    ("cGcPlayerShipOwnership", "1.24", "Multi-ship ownership arrived in Path Finder (1.2)."),
    ("cGcPlayerFreighterOwnership", "1.13", "Freighter purchase arrived in Foundation (1.1)."),
]

# Per-function overrides for cases a class-prefix rule can't express: a single method
# whose feature postdates its class (e.g. freighter *bases* vs freighter purchase), or
# a lone late feature in a class most of whose methods are old (cGcPlayer::GetDominantHand
# among 10 old cGcPlayer methods). Same (first-supported-build | None, note) shape.
# Checked before RULES. Each is corroborated by a string/imm probe recorded in
# offsets.json's _unresolved note for that entry.
EXACT = {
    "cGcFrontendPageClaimBase::DoBaseClaimOptions":
        ("1.13", "Base-claim UI depends on base building (Foundation 1.1); absent in 1.09.1."),
    "cGcQuickActionMenu::TriggerAction":
        ("1.13", "Quick-action menu arrived in Foundation (1.1); absent in 1.09.1."),
    "cGcPlayerFreighterOwnership::ResetPlayerFreighterBase":
        (None, "Freighter bases post-date 1.38 (arrived in NEXT 1.5); the base-reset OSD string and its imm64 are absent from every 1.x exe."),
    "cGcBuilding::DestroyIntersectingVolcanoes":
        (None, "Volcano landmarks post-date 1.38; the 'VOLCANO' immediate is absent from every 1.x .text/.rdata."),
    "cGcPlayer::GetDominantHand":
        (None, "VR (OpenVR) support arrived in Beyond (2.0, 2019); the cTkHmdOpenVR accessor is absent from all four builds."),
    "cGcScanEvent::UpdateSpaceStationLocation":
        (None, "Space-station settlements post-date 1.38; the SettlementConstructionLevel string is absent from every 1.x exe."),
}


def rule_for(name):
    if name in EXACT:
        return EXACT[name]
    for prefix, first, note in RULES:
        if name.startswith(prefix):
            return first, note
    return VERSIONS[0], None


def main():
    write = "--write" in sys.argv
    data = json.loads(OFFSETS.read_text())
    functions = data["functions"]
    targets = sorted({e["name"] for e in json.loads(TARGETS.read_text())})

    added_names = flagged = 0
    for name in targets:
        entry = functions.setdefault(name, {})
        if not any(str(entry.get(v, "")).startswith("0x") for v in VERSIONS):
            pass  # counted below either way
        first, note = rule_for(name)
        # An EXACT override is authoritative and replaces any stale prefix-rule note;
        # a prefix rule only fills a note in when the entry has none.
        if note and (name in EXACT or "_note" not in entry):
            entry["_note"] = note
        supported = VERSIONS[VERSIONS.index(first):] if first else []
        for v in VERSIONS:
            val = entry.get(v)
            if isinstance(val, str) and val.startswith("0x"):
                continue
            entry[v] = NOT_FOUND if v in supported else NOT_IN
            flagged += 1
        if len(entry) == len(VERSIONS) + ("_note" in entry):
            added_names += 1 if name not in functions else 0

    # Keep version keys in a stable order for readability.
    for name, entry in functions.items():
        ordered = {k: entry[k] for k in ("_comment", "_note") if k in entry}
        ordered.update({v: entry[v] for v in VERSIONS if v in entry})
        for k in entry:
            if k not in ordered:
                ordered[k] = entry[k]
        functions[name] = ordered

    total = len(targets)
    per_version = {
        v: sum(1 for n in targets if str(functions[n].get(v, "")).startswith("0x"))
        for v in VERSIONS
    }
    not_in = {
        v: sum(1 for n in targets if functions[n].get(v) == NOT_IN) for v in VERSIONS
    }
    print(f"surface: {total} functions, {flagged} version-slots flagged")
    for v in VERSIONS:
        print(f"  {v}: {per_version[v]} found, {not_in[v]} not-in-version, "
              f"{total - per_version[v] - not_in[v]} not-yet-found")
    if write:
        OFFSETS.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {OFFSETS}")


if __name__ == "__main__":
    main()
