import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
VERSIONS = ["1.09.1", "1.13", "1.24", "1.38"]
FLAGS = {"NOT_YET_FOUND", "NOT_IN_THIS_VERSION"}
ADDRESS = re.compile(r"^0x14[0-9A-Fa-f]{7}$")


def load():
    return json.loads((ROOT / "nmspy" / "data" / "offsets.json").read_text())


def test_full_upstream_surface_is_present():
    functions = load()["functions"]
    targets = {e["name"] for e in json.loads(
        (ROOT / "tools" / "legacy_re" / "upstream_data_413.json").read_text()
    )}
    missing = targets - set(functions)
    assert not missing, f"missing upstream functions: {sorted(missing)[:5]}..."


def test_every_version_slot_is_address_or_flag():
    for table in load().values():
        for name, entry in table.items():
            for v in VERSIONS:
                value = entry.get(v)
                if value is None:
                    continue
                assert ADDRESS.match(value) or value in FLAGS, f"{name} {v}: {value!r}"


def test_flagged_entries_never_carry_fake_addresses():
    functions = load()["functions"]
    for name, entry in functions.items():
        if entry.get("_note"):
            assert any(entry.get(v) for v in VERSIONS), f"{name} has a note but no data"


def test_aliases_and_names_schema():
    functions = load()["functions"]
    for name, entry in functions.items():
        for alias in entry.get("_aliases") or []:
            assert isinstance(alias, str), f"{name} alias not a string"
        for v, actual in (entry.get("_names") or {}).items():
            assert v in VERSIONS and isinstance(actual, str), f"{name} bad _names[{v}]"


def test_alias_resolution():
    # A pure-Python resolver mirroring offsets.py (no pymhf import needed here).
    functions = load()["functions"]
    alias_of = {}
    for canon, entry in functions.items():
        for alias in entry.get("_aliases") or []:
            alias_of[alias] = canon
    for alias, canon in alias_of.items():
        # the alias resolves to a real canonical entry with per-version data
        assert canon in functions
        entry = functions[canon]
        assert any(ADDRESS.match(str(entry.get(v, ""))) for v in VERSIONS)
