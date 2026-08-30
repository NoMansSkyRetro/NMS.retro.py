import json, sys
from collections import defaultdict, Counter
import propagate_symbols as ps

ref_side, ref_names, ref_mangled = ps.load_side_413()
vas_by_name = defaultdict(list)
for va, n in ref_names.items():
    vas_by_name[n].append(va)
targets = sorted(json.load(open('out/hunt_batches.json'))['solar_galaxy'])
offs = json.load(open('../../nmspy/data/offsets.json'))['functions']
hints = json.load(open('out/target_hints.json'))

# target -> list of 4.13 vas
tvas = {t: vas_by_name.get(t, []) for t in targets}

def load_seed(side, build):
    seed = {}
    prop = json.load(open(f'out/propagated_{build}.json'))
    for name, v in prop.items():
        vs = vas_by_name.get(name, [])
        if len(vs) == 1:
            seed[vs[0]] = int(v['address'], 16)
    for name, e in offs.items():
        a = e.get(build)
        if isinstance(a, str) and a.startswith('0x'):
            vs = vas_by_name.get(name, [])
            if len(vs) == 1:
                seed[vs[0]] = int(a, 16)
    return seed

def resolve_build(build, verbose=True):
    side = ps.load_side_build(build)
    sizemap = {f[0]: f[1] for f in side.functions}
    seed = load_seed(side, build)
    found = {}  # target name -> legacy addr

    def score_target(tva, seed_now, taken):
        # collect weighted constraints from mapped neighbours
        cons = []  # (weight, set)
        for c in ref_side.callees.get(tva, ()):
            if c in seed_now:
                s = side.callers.get(seed_now[c], set())
                if 0 < len(s) <= 400:
                    cons.append((1.0/len(s), s))
        for c in ref_side.callers.get(tva, ()):
            if c in seed_now:
                s = side.callees.get(seed_now[c], set())
                if 0 < len(s) <= 400:
                    cons.append((1.0/len(s), s))
        if len(cons) < 2:
            return None, cons
        score = Counter()
        hits = Counter()
        for w, s in cons:
            for a in s:
                if a in taken:
                    continue
                score[a] += w
                hits[a] += 1
        # candidates must be hit by >=2 distinct constraints
        cand = [(sc, hits[a], a) for a, sc in score.items() if hits[a] >= 2]
        cand.sort(reverse=True)
        return cand, cons

    for it in range(8):
        seed_now = dict(seed)
        for nm, la in found.items():
            for v in tvas[nm]:
                seed_now[v] = la
        taken = set(seed_now.values())
        added = 0
        for t in targets:
            if t in found:
                continue
            best = None
            for tva in tvas[t]:
                cand, cons = score_target(tva, seed_now, taken)
                if not cand:
                    continue
                if best is None or cand[0] > best[0]:
                    best = (cand[0], cand, tva)
            if not best:
                continue
            (topsc, tophits, topaddr), cand, tva = best
            # uniqueness/margin: winner distinct, hits>=3 OR (hits>=2 and margin)
            margin = (cand[0][0] - cand[1][0]) if len(cand) > 1 else cand[0][0]
            ml = hints[t]['modern_length'] or 0
            sz = sizemap.get(topaddr, 0)
            szok = ml == 0 or (0.15*ml <= sz <= 4*ml)
            if tophits >= 3 and margin > 1e-9 and szok:
                found[t] = topaddr
                added += 1
                if verbose:
                    print(f'  [{build}] {t} = {hex(topaddr)} score={topsc:.3f} hits={tophits} margin={margin:.3f} size={sz}/{ml}', file=sys.stderr)
        if added == 0:
            break
    return side, sizemap, seed, found

if __name__ == '__main__':
    b = sys.argv[1] if len(sys.argv) > 1 else '1.38'
    side, sizemap, seed, found = resolve_build(b)
    print(f'== {b}: resolved {len(found)}/{len(targets)} ==', file=sys.stderr)
    for t in targets:
        print(f'{t}: {hex(found[t]) if t in found else "UNRESOLVED"}')
