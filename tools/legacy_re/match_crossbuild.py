"""Match each 1.38-located function to its twin in an older build by structural
fingerprint of the decompiled bodies (params, return kind, named library calls, distinctive
constants, size ratio). Deterministic; prints a ranked pick per (target, build) plus a JSON
of confident picks for the finder. Confirmation is by fingerprint agreement, not a guess.

Needs: out/orig_138.json (1.38 originals), out/cand_<build>.json (candidates),
out/older_leads.json (target -> candidate addrs per build), out/fleet_confirmed.json.

    python match_crossbuild.py
"""
import json
import re
from pathlib import Path

HERE = Path(__file__).parent
CONF = json.loads((HERE / "out" / "fleet_confirmed.json").read_text())["confirmed"]
LEADS = json.loads((HERE / "out" / "older_leads.json").read_text())
ORIG = json.loads((HERE / "out" / "orig_138.json").read_text())
CANDS = {b: json.loads((HERE / "out" / f"cand_{b.replace('.', '')}.json").read_text())
         for b in ("1.24", "1.13", "1.09.1")}

# stable-across-builds tokens: named lib calls and distinctive literals
NAMED = re.compile(r"\b(AK::[A-Za-z_:]+|strn?c(?:py|at|mp)|_?strupr|PostEvent|SetState|"
                   r"GetIDFromString|QueryPerformanceCounter|WaitForSingleObject|ReleaseMutex|"
                   r"SetAttenuationScalingFactor|SetRTPCValue|GetPlayerFromId)\b")
HEXCONST = re.compile(r"0x[0-9a-fA-F]{6,}")
STRLIT = re.compile(r'"([^"]{3,})"')


def fingerprint(decomp):
    if not decomp:
        return None
    first = next((l for l in decomp.splitlines() if "FUN_" in l and "(" in l and "=" not in l.split("(")[0]), "")
    ret = first.strip().split(" ")[0] if first else "?"
    params = first.count(",") + 1 if "(" in first and ")" in first and "(void)" not in first.replace(" ", "") else 0
    named = set(m.group(0) for m in NAMED.finditer(decomp))
    consts = set(c.lower() for c in HEXCONST.findall(decomp) if c.lower() not in ("0xffffffff",))
    strs = set(STRLIT.findall(decomp))
    nfun = decomp.count("FUN_")
    return {"ret": ret, "params": params, "named": named, "consts": consts, "strs": strs, "nfun": nfun}


def score(a, b, size_a, size_b):
    if not a or not b:
        return -1, []
    why = []
    s = 0.0
    if a["ret"] == b["ret"]:
        s += 1; why.append("ret")
    if a["params"] == b["params"]:
        s += 1.5; why.append(f"params={a['params']}")
    shared_named = a["named"] & b["named"]
    if shared_named:
        s += 2 * len(shared_named); why.append("named:" + ",".join(sorted(shared_named))[:40])
    shared_str = a["strs"] & b["strs"]
    if shared_str:
        s += 3 * len(shared_str); why.append("str:" + ",".join(sorted(shared_str))[:30])
    shared_const = a["consts"] & b["consts"]
    if shared_const:
        s += 1.5 * len(shared_const); why.append("const:" + ",".join(sorted(shared_const))[:30])
    if size_b and size_a:
        ratio = size_b / size_a
        if 0.7 <= ratio <= 1.4:
            s += 1; why.append(f"size~{ratio:.2f}")
    return s, why


def main():
    picks = {"1.24": {}, "1.13": {}, "1.09.1": {}}
    for target, va138 in CONF.items():
        o = ORIG.get(va138)
        if not o:
            continue
        fo = fingerprint(o.get("decomp"))
        for b in ("1.24", "1.13", "1.09.1"):
            cand_addrs = [a for a, *_ in LEADS.get(f"{target}||{b}", [])]
            ranked = []
            for a in cand_addrs:
                c = CANDS[b].get(a)
                if not c:
                    continue
                sc, why = score(fo, fingerprint(c.get("decomp")), o.get("size"), c.get("size"))
                ranked.append((sc, a, c.get("size"), why))
            ranked.sort(reverse=True)
            if not ranked:
                continue
            best = ranked[0]
            runner = ranked[1][0] if len(ranked) > 1 else -1
            print(f"\n{target}  [{b}]  1.38={va138}({o.get('size')}B)")
            for sc, a, csz, why in ranked[:3]:
                print(f"    {sc:5.1f}  {a} ({csz}B)  {why}")
            # confident: clear best (>=4 and margin >=2 over runner-up), or exact-size + params/ret
            if best[0] >= 4 and best[0] - runner >= 2:
                picks[b][target] = best[1]
                print(f"    -> PICK {best[1]}")
    (HERE / "out" / "crossbuild_picks.json").write_text(json.dumps(picks, indent=1))
    tot = sum(len(v) for v in picks.values())
    print(f"\nconfident picks: {tot}  ({ {b: len(v) for b, v in picks.items()} })")


if __name__ == "__main__":
    main()
