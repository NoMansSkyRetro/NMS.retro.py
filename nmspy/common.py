import nmspy.data.types as nms


class GameData:
    GcApplication: nms.cGcApplication = None  # type: ignore

    # Convenience accessors (player, simulation, game state, ...) return once their
    # legacy struct offsets are mapped; see PLAN.md phase 3.


gameData = GameData()
