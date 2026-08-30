# Identification log

How each entry in `nmspy/data/offsets.json` was found. Commands are `explore.py`
subcommands; all addresses assume the 0x140000000 preferred base. 1.09.1 columns stay
null until its Steam decompilation database finishes building (the earlier "1.09.1"
analysis was of the GOG binary, whose addresses do not transfer).

## The application FSM cluster

The legacy app is a state machine: `cGcApplication` derives from `cTkFSM`, and the app
FSM object is a **static global**, not heap-allocated as in the modern game. State IDs
are mixed-case strings (`AppBoot`, `AppCoreServices`, `AppGlobalLoad`, `AppLocalLoad`,
`AppView`, `AppShutdown`) unlike the modern all-caps IDs; 1.09.1 has no
`ModeSelector` state because game modes only arrived later.

Chain of identification, per build:

1. `grep <build> "FSM IGNORED"` — the log string
   `"\n - FSM IGNORED REQUEST : -> [%s], already transitioning to [%s]\n"` appears in
   every function that requests a state transition. Most call sites inline the
   request, but one hit is a tiny standalone function (74 bytes in 1.09/1.13, 72 in
   1.24/1.38): **`cTkFSM::StateChange`**. Its body writes the requested state ID into
   the pending-state slot (`this->mpData[0x18..0x30]`) after checking it currently
   holds `FSM_NoState`. In 1.24+ it gains the `lpUserData`/`lbForceRestart` parameters
   that the modern signature also has.
2. The 274-byte function immediately after it is **`cTkFSM::Construct`** (confirmed:
   takes the FSM, a state table, and the initial state ID `AppBoot`).
3. `grep` for the Construct address — its one external caller is
   **`cGcApplication::Construct`**: allocates the application data block
   (`0x8a5b60` bytes in 1.13, `0x8ae8e0` in 1.24, `0x841360` in 1.38), stores the
   pointer in a global (**`cGcApplicationData*`**), and constructs the FSM on the
   static **`cGcApplication`** global.
4. `grep "<app global> = "` — the static initializer that stamps the vtable pointer
   onto the app global. `vtable <build> <addr>` then lists the virtuals:
   slot 1 = `cTkFSM::Construct` (already known, cross-check), slot 2 (129 bytes in
   every build) = **`cTkFSM::Update`**.
5. `grep` for the `cTkFSM::Update` address — its one external caller is
   **`cGcApplication::Update`**, the per-frame main loop tick:
   `QueryPerformanceCounter`, two virtual queries, `cTkFSM::Update(&app, dt)`, then a
   virtual render call. Identical shape in every build.

## Resulting addresses

| symbol | 1.13 | 1.24 | 1.38 |
|--------|------|------|------|
| cGcApplication::Construct | 0x1404ADF60 | 0x140561C80 | 0x140675900 |
| cGcApplication::Update | 0x1404B5BA0 | 0x14056B950 | 0x140680550 |
| cTkFSM::Construct | 0x140D4B320 | 0x140F0DC30 | 0x1410D3F50 |
| cTkFSM::Update | 0x140D4B460 | 0x140F0DDC0 | 0x1410D40E0 |
| cTkFSM::StateChange | 0x140D4B2D0 | 0x140F0DBE0 | 0x1410D3F00 |
| cGcApplication (global) | 0x1417F6C80 | 0x141A433F0 | 0x142033690 |
| cGcApplicationData* (global) | 0x1417F6CB8 | 0x141A43428 | 0x1420336C8 |

## Notes for later phases

- State-change notification: most `StateChange` call sites are inlined, so hooking
  `cTkFSM::StateChange` misses transitions. Hook `cTkFSM::Update` and watch the FSM's
  current/pending state strings instead.
- `cTkFSM` layout (from the StateChange body): `this+0x18` points at a data block
  whose `+0x18` is the pending-state `cTkFixedString<0x10>`, `+0x28` user data,
  `+0x30` force-restart flag.
- The app data block (`cGcApplicationData*` global) is the legacy analogue of the
  modern `cGcApplication::mpData`; sub-objects live at fixed offsets inside it
  (e.g. `+0x30` referenced in every build's Construct).
