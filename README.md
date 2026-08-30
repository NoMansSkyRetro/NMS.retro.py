# NMS.retro.py

NMS.retro.py is a fork of [monkeyman192's NMS.py](https://github.com/monkeyman192/NMS.py)
that targets four **legacy** No Man's Sky builds instead of the modern game:

| Version | Update | Steam build |
|---------|--------|-------------|
| 1.09.1  | Release (final patch) | 2016-10-13 |
| 1.13    | Foundation | 2016-12-08 |
| 1.24    | Path Finder | 2017-03-23 |
| 1.38    | Atlas Rises | 2017-09-29 |

The running build is detected automatically from the exe's PE header timestamp, and
game functions are located by per-build static addresses (`nmspy/data/offsets.json`)
rather than byte-pattern scanning; these builds are frozen forever, so their addresses
are too. Every address is derived reproducibly with the scripts in `tools/legacy_re/`,
which document the whole reverse-engineering process.

See [PLAN.md](PLAN.md) for the retargeting design and current phase.

**NOTE:** Any responsibility for broken saves is entirely on the users of this library.
This library will never contain functions relating to online functionality.

## Installation

Install from a clone of this repository (the `nmspy` package on PyPI is the modern
upstream, not this fork):

```
python -m pip install -e .
```

This installs NMS.py's dependency [`pyMHF`](https://github.com/monkeyman192/pyMHF)
as well.

## Usage

```
pymhf run nmspy
```

When configuring pyMHF, point it at a legacy install's `NMS.exe` (there is no Steam
app id to launch through; Steam only serves the modern build). If NMS.py starts up
successfully you should see two extra windows; an auto-created GUI from pyMHF, and a
terminal window which will show the logs for pyMHF.

## Writing mods

See the [pyMHF docs](https://monkeyman192.github.io/pyMHF/) for the framework
basics. Hook coverage differs per build: a hook whose address is not yet mapped for
the running build is disabled with a warning, and `nmspy.versions.CURRENT_VERSION`
tells you which build you are on.

## Contributing

The most valuable contribution is mapping more functions and struct fields. Read
`tools/legacy_re/README.md` for the methodology and tooling; new addresses go into
`nmspy/data/offsets.json` with a note in `tools/legacy_re/findings.md`, and
`tools/legacy_re/verify_offsets.py` must pass.

## Credits

NMS.py is by [monkeyman192](https://github.com/monkeyman192), built on minhook,
cyminhook and pymem, with contributions and RE help from vitalised, gurren3, RaYRoD
and many others; see the upstream repository for the full credits. The retro
retargeting is by the [NoMansSkyRetro](https://github.com/NoMansSkyRetro) organization.
