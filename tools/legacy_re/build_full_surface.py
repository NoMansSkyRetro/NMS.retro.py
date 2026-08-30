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
    ("nvg", None, "NanoVG UI drawing only exists in modern builds; no NanoVG shader strings in any 1.x exe."),
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


def rule_for(name):
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
        if note and "_note" not in entry:
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
