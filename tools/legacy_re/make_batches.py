"""Group the still-NOT_YET_FOUND upstream functions into balanced hunt batches.

Writes out/hunt_batches.json: {batch_name: {func: {build: status}}}. Re-run whenever
offsets.json changes to reflect what is still missing.

    python make_batches.py
"""

import json
from collections import defaultdict
from pathlib import Path

OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"
TARGETS = Path(__file__).parent / "upstream_data_413.json"
OUT = Path(__file__).parent / "out" / "hunt_batches.json"
VER = ["1.09.1", "1.13", "1.24", "1.38"]

# (batch, prefixes) — first match wins; app_misc is the catch-all.
RULES = [
    ("engine_scene", ("Engine::",)),
    ("renderer", ("cEg", "EgInstancedModelExtension", "GeometryStreaming", "cTkGraphicsAPI", "cTkTexture")),
    ("filesystem_meta", ("cTkFileSystem", "cTkAsyncIOManager", "cTkMetaData", "cTkResource", "XMLNode", "GenerateModdedFilepath", "MiniDumpFunction", "cTkEngineUtils")),
    ("player_core", ("cGcPlayer::", "cGcPlayerState")),
    ("player_aux", ("cGcPlayerWeapon", "cGcPlayerWanted", "cGcPlayerCommunicator", "cGcPlayerCharacterComponent", "cGcPlayerDiscoveryHelper", "cGcPlayerEnvironment", "cGcPlayerHUD")),
    ("ship_space", ("cGcPlayerShipOwnership", "cGcSpaceship", "cGcShipHUD", "cGcPlayerFreighterOwnership", "cGcPlayerVehicleOwnership")),
    ("planet_terrain", ("cGcPlanet", "cGcTerrainEditorBeam", "cGcEnvironment", "cGcSky", "cGcResourceCustomisation")),
    ("solar_galaxy", ("cGcSolarSystem", "SolarQueryResult", "cGcGalaxyAttribute", "cGcGalaxyVoxel", "cGcGalaxyStar", "cGcNameGenerator", "cGcGalaxyAttributesAtAddress")),
    ("discovery_scan", ("cGcBinoculars", "cGcScanEvent", "cGcDiscoveryManager", "cGcVisitedSystemsBuffer")),
    ("frontend_ui", ("cGcFrontend", "cGcOptionsPageUI", "cGcPhotoModeUI", "cGcGalaxyMap")),
    ("hud_gui", ("cGcNGui", "cGcHUD", "cGcMarker", "cGcPositionMarker")),
    ("interaction_trade", ("cGcInteraction", "cGcSimpleInteraction", "cGcPersistentInteraction", "cGcRewardManager", "cGcPurchaseableItem", "cGcInventoryStore", "cGcNotificationSequence")),
    ("base_building", ("cGcBaseBuilding", "cGcBaseSearch", "cGcBuilding", "cGcPlayerBasePersistentBuffer")),
    ("physics_gravity", ("cTkDynamicGravityControl", "cTkRigidBody", "cGcDestructableComponent")),
    ("app_misc", ()),
]


def main():
    off = json.loads(OFFSETS.read_text())["functions"]
    targets = {e["name"] for e in json.loads(TARGETS.read_text())}
    nyf = {
        n: {v: off[n].get(v) for v in VER}
        for n in sorted(targets)
        if any(off.get(n, {}).get(v) == "NOT_YET_FOUND" for v in VER)
    }
    batches = defaultdict(dict)
    for name, status in nyf.items():
        for batch, prefixes in RULES:
            if not prefixes or any(name.startswith(p) for p in prefixes):
                batches[batch][name] = status
                break
    out = {b: names for b, names in batches.items() if names}
    OUT.write_text(json.dumps(out, indent=1) + "\n")
    for b, names in sorted(out.items(), key=lambda kv: -len(kv[1])):
        print(f"{b}: {len(names)}")
    print("total NOT_YET_FOUND functions:", sum(len(v) for v in out.values()))


if __name__ == "__main__":
    main()
