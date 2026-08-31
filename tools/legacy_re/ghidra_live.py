"""Live Ghidra access to a legacy build's analyzed project via pyghidra.

Our static SQLite decomp only has decompiled text; Ghidra's own program database has
the real ReferenceManager (data refs, computed/indirect calls, vtable refs) and the
decompiler on demand. This opens the EXISTING analyzed project read-only (no
re-analysis) and exposes the queries a hand-golf session needs.

    python ghidra_live.py smoke 1.38
    python ghidra_live.py xrefs 1.38 0x140f81250        # refs to/from a function
    python ghidra_live.py decompile 1.38 0x140f81250
    python ghidra_live.py vtables 1.38 cGcMarkerPoint    # vtable(s) near a class string

Opening the JVM + program costs ~20s, so prefer driving it from a session function
(see `open_program`) that runs many queries in one JVM.
"""

import sys

GHIDRA_INSTALL_DIR = r"E:\ghidra_12.1.2_PUBLIC"
PROJECTS = {
    "1.09.1": (r"E:\NMSLegacy_Decomp\NMS1091_GHIDRA_PROJ", "NMS1091", "NMS.exe"),
    "1.13": (r"E:\NMSLegacy_Decomp\NMS113_GHIDRA_PROJ", "NMS113", "NMS.exe"),
    "1.24": (r"E:\NMSLegacy_Decomp\NMS124_GHIDRA_PROJ", "NMS124", "NMS.exe"),
    "1.38": (r"E:\NMSLegacy_Decomp\NMS138_GHIDRA_PROJ", "NMS138", "NMS.exe"),
}


def open_program(build):
    import pyghidra

    if not pyghidra.started():
        pyghidra.start(install_dir=GHIDRA_INSTALL_DIR)
    proj_dir, proj_name, prog = PROJECTS[build]
    # read-only open of the already-analyzed program (matches OpenNMS's pattern)
    return pyghidra.open_program(
        None, project_location=proj_dir, project_name=proj_name, program_name=prog,
        analyze=False, nested_project_location=False,
    )


def _fm(program):
    return program.getFunctionManager()


def smoke(build):
    with open_program(build) as api:
        prog = api.getCurrentProgram()
        fm = _fm(prog)
        print("program:", prog.getName())
        print("image base:", hex(prog.getImageBase().getOffset()))
        print("function count:", fm.getFunctionCount())
        # a known function
        f = fm.getFunctionAt(prog.getAddressFactory().getDefaultAddressSpace().getAddress(0x140680550))
        print("0x140680550 =", f.getName() if f else None)


def _addr(prog, va):
    return prog.getAddressFactory().getDefaultAddressSpace().getAddress(va)


def xrefs(build, va):
    with open_program(build) as api:
        prog = api.getCurrentProgram()
        ref = prog.getReferenceManager()
        fm = _fm(prog)
        a = _addr(prog, va)
        f = fm.getFunctionAt(a)
        print(f"function: {f.getName() if f else '?'} @ {hex(va)}")
        print("--- refs TO this function (callers, incl. indirect/data) ---")
        for r in ref.getReferencesTo(a):
            src = r.getFromAddress()
            cf = fm.getFunctionContaining(src)
            print(f"  {r.getReferenceType()}  from {hex(src.getOffset())}  in {cf.getName() if cf else '?'}"
                  f" @ {hex(cf.getEntryPoint().getOffset()) if cf else ''}")
        print("--- refs FROM this function ---")
        body = f.getBody() if f else None
        if body:
            seen = set()
            it = ref.getReferenceIterator(body.getMinAddress())
            while it.hasNext():
                r = it.next()
                if not body.contains(r.getFromAddress()):
                    break
                to = r.getToAddress()
                tf = fm.getFunctionAt(to)
                if tf and tf.getEntryPoint().getOffset() not in seen:
                    seen.add(tf.getEntryPoint().getOffset())
                    print(f"  {r.getReferenceType()}  -> {tf.getName()} @ {hex(to.getOffset())}")


def decompile(build, va):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    with open_program(build) as api:
        prog = api.getCurrentProgram()
        f = _fm(prog).getFunctionAt(_addr(prog, va))
        di = DecompInterface()
        di.openProgram(prog)
        res = di.decompileFunction(f, 60, ConsoleTaskMonitor())
        print(res.getDecompiledFunction().getC())


def _decomp_iface(prog):
    from ghidra.app.decompiler import DecompInterface
    di = DecompInterface()
    di.openProgram(prog)
    return di


def dossier(build, out_path, anchor_vas):
    """Dump, in ONE JVM open, everything a matching agent needs for a call-anchor walk.

    For each mapped anchor VA: its decompiled body (the calling context), and every
    function it calls (real ReferenceManager edges, so indirect/vtable calls too) with
    address, Ghidra name, size, and the callee's own callee-names (named library
    functions among them are strong fingerprints). Anchor bodies plus callee bodies
    within a size band are decompiled so an agent can match by behaviour against the
    4.13 target profile. Writes JSON; no address is committed here.

        python ghidra_live.py dossier 1.38 out/dossier_1.38.json 0x140CA2820 0x140DD3780
    """
    import json

    with open_program(build) as api:
        from ghidra.util.task import ConsoleTaskMonitor
        prog = api.getCurrentProgram()
        ref = prog.getReferenceManager()
        fm = _fm(prog)
        di = _decomp_iface(prog)
        mon = ConsoleTaskMonitor()

        def name_size(va):
            f = fm.getFunctionAt(_addr(prog, va))
            return (f.getName(), int(f.getBody().getNumAddresses())) if f else (None, 0)

        def body_decomp(f):
            try:
                r = di.decompileFunction(f, 60, mon)
                return r.getDecompiledFunction().getC() if r and r.getDecompiledFunction() else None
            except Exception as e:  # noqa: BLE001
                return f"<decompile failed: {e}>"

        def callees_of(f):
            out = {}
            body = f.getBody()
            it = ref.getReferenceIterator(body.getMinAddress())
            while it.hasNext():
                r = it.next()
                if not body.contains(r.getFromAddress()):
                    break
                tf = fm.getFunctionAt(r.getToAddress())
                if tf:
                    va = tf.getEntryPoint().getOffset()
                    out[va] = (tf.getName(), int(tf.getBody().getNumAddresses()))
            return out

        result = {}
        for anchor in anchor_vas:
            af = fm.getFunctionAt(_addr(prog, anchor))
            if af is None:
                result[f"0x{anchor:X}"] = {"error": "anchor not a function start"}
                continue
            callees = callees_of(af)
            entry = {
                "anchor_name": af.getName(),
                "anchor_size": int(af.getBody().getNumAddresses()),
                "anchor_decomp": body_decomp(af),
                "callees": [],
            }
            for va, (nm, sz) in sorted(callees.items()):
                cf = fm.getFunctionAt(_addr(prog, va))
                grandkids = sorted({n for n, _ in callees_of(cf).values()} if cf else set())
                # named grandchildren (non-FUN_) are the useful fingerprints
                named_gk = [g for g in grandkids if not g.startswith("FUN_")]
                entry["callees"].append({
                    "va": f"0x{va:X}", "name": nm, "size": sz,
                    "named_callees": named_gk,
                    "decomp": body_decomp(cf) if cf and sz <= 1600 else None,
                })
            result[f"0x{anchor:X}"] = entry
            print(f"[dossier] {af.getName()} @ 0x{anchor:X}: {len(callees)} callees", file=sys.stderr)

        with open(out_path, "w") as fh:
            json.dump(result, fh, indent=1)
        print(f"[dossier] wrote {out_path}", file=sys.stderr)


def decompmany(build, out_path, vas):
    """Decompile a list of function VAs in ONE JVM open; write {va: {name,size,decomp}}.

        python ghidra_live.py decompmany 1.38 out/cluster.json 0x14066BB30 0x14066BC40 ...
    """
    import json

    with open_program(build) as api:
        from ghidra.util.task import ConsoleTaskMonitor
        prog = api.getCurrentProgram()
        fm = _fm(prog)
        di = _decomp_iface(prog)
        mon = ConsoleTaskMonitor()
        out = {}
        for va in vas:
            f = fm.getFunctionAt(_addr(prog, va))
            if f is None:
                out[f"0x{va:X}"] = {"error": "not a function start"}
                continue
            try:
                r = di.decompileFunction(f, 60, mon)
                c = r.getDecompiledFunction().getC() if r and r.getDecompiledFunction() else None
            except Exception as e:  # noqa: BLE001
                c = f"<decompile failed: {e}>"
            out[f"0x{va:X}"] = {"name": f.getName(), "size": int(f.getBody().getNumAddresses()), "decomp": c}
        with open(out_path, "w") as fh:
            json.dump(out, fh, indent=1)
        print(f"[decompmany] wrote {out_path} ({len(vas)} funcs)", file=sys.stderr)


def main():
    cmd = sys.argv[1]
    build = sys.argv[2]
    if cmd == "smoke":
        smoke(build)
    elif cmd == "xrefs":
        xrefs(build, int(sys.argv[3], 16))
    elif cmd == "decompile":
        decompile(build, int(sys.argv[3], 16))
    elif cmd == "decompmany":
        decompmany(build, sys.argv[3], [int(a, 16) for a in sys.argv[4:]])
    elif cmd == "dossier":
        out_path = sys.argv[3]
        anchor_vas = [int(a, 16) for a in sys.argv[4:]]
        dossier(build, out_path, anchor_vas)


if __name__ == "__main__":
    main()
