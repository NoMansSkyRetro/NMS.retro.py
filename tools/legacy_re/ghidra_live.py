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


def main():
    cmd = sys.argv[1]
    build = sys.argv[2]
    if cmd == "smoke":
        smoke(build)
    elif cmd == "xrefs":
        xrefs(build, int(sys.argv[3], 16))
    elif cmd == "decompile":
        decompile(build, int(sys.argv[3], 16))


if __name__ == "__main__":
    main()
