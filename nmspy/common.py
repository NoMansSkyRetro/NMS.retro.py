from typing import Optional

import nmspy.data.types as nms


class GameData:
    """Singletons and accessors shared by all mods.

    Every accessor returns None when the underlying object or field is not mapped in
    the running build, so mods can chain `if x is not None` checks and degrade
    gracefully instead of crashing (see PLAN.md: the framework does the gating).
    """

    GcApplication: nms.cGcApplication = None  # type: ignore
    Simulation: nms.cGcSimulation = None  # type: ignore

    @property
    def simulation(self) -> Optional[nms.cGcSimulation]:
        return self.Simulation

    @property
    def game_state(self):
        # Chain unmapped: needs the cGcApplication data layout (PLAN.md phase 3).
        return None

    @property
    def player(self):
        return None

    @property
    def player_state(self):
        return None

    @property
    def environment(self):
        return None

    @property
    def player_environment(self):
        return None


gameData = GameData()
