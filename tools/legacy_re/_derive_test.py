import json, sys
from collections import Counter
import propagate_symbols as ps

IMM_1BD1 = 0x1BD11BDAA9FC1A22

def build(build):
    side = ps.load_side_build(build)
    size = {f[0]: f[1] for f in side.functions}
    starts = set(size)
    name2la = {}
    for name, v in json.load(open(f'out/propagated_{build}.json')).items():
        name2la[name] = int(v['address'], 16)
    offs = json.load(open('../../nmspy/data/offsets.json'))['functions']
    for name, e in offs.items():
        a = e.get(build)
        if isinstance(a, str) and a.startswith('0x'):
            name2la[name] = int(a, 16)
    return side, size, starts, name2la

def derive(build):
    side, size, starts, A = build_ctx = build_all(build)
    return build_ctx

def build_all(b):
    side, size, starts, A = build(b)
    mapped = set(A.values())
    def callees(x): return side.callees.get(x, set())
    def callers(x): return side.callers.get(x, set())
    def imm_funcs(imm): return {k for k, toks in side.prints.items() if ('imm', imm) in toks}
    found = {}
    log = []
    def a(name):
        return A.get(name)

    # 1. ClassifyStarSystem: common callee of 3 UI anchors; disambiguate via imm cluster
    cluster = imm_funcs(IMM_1BD1)
    populate = max(cluster, key=lambda x: size.get(x, 0)) if cluster else None
    if populate:
        found['cGcGalaxyVoxelGenerator::Populate'] = populate
    ui = [a(n) for n in ['cGcDiscoveryPageData::PopulateFromDiscoveryExport',
                          'cGcFrontendPageDiscovery::DoSystemPopup',
                          '?ApplyMapFilterToVoxel@Data@cGcGalaxyMap@@QEAAXVcGcGalacticVoxelCoordinate@@W4MapFilter@2@@Z']
          if a(n)]
    starsystem = None
    if len(ui) >= 2:
        common = set.intersection(*[callees(x) for x in ui])
        common = {c for c in common if c not in mapped}
        # ClassifyStarSystem is the common callee that itself calls an imm-cluster member
        cand = [c for c in common if callees(c) & cluster]
        if len(cand) == 1:
            starsystem = cand[0]
            found['cGcGalaxyAttributeGenerator::ClassifyStarSystem'] = starsystem
    # 3. StarKeyAttr: imm-cluster member (not populate) called by ClassifyStarSystem
    if starsystem:
        sk = [c for c in callees(starsystem) & cluster if c != populate]
        if len(sk) == 1:
            found['cGcGalaxyAttributeGenerator::ClassifyStarKeyAttributes'] = sk[0]
        # 4. StarAttrSetDefaults: other callee of StarSystem, a leaf, in common set
        others = [c for c in callees(starsystem) if c not in cluster and c not in mapped
                  and len(callees(c)) == 0]
        if starsystem in locals().get('common', set()):
            pass
        cand_sd = [c for c in others if c in set.intersection(*[callees(x) for x in ui])]
        if len(cand_sd) == 1:
            found['cGcGalaxyStarAttributesData::SetDefaults'] = cand_sd[0]
    # 5. Classify: callee of PollToPrepare that calls ClassifyStarSystem
    ptp = a('cGcSolarSystem::PollToPrepare')
    classify = None
    if starsystem and ptp:
        cand = [c for c in callers(starsystem) & callees(ptp)]
        if len(cand) == 1:
            classify = cand[0]
            found['cGcGalaxyAttributesAtAddress::Classify'] = classify
    # 6. ClassifyVoxel: callee of Classify also called by Populate
    if classify and populate:
        cand = [c for c in (callees(classify) & callees(populate)) if c not in mapped]
        if len(cand) == 1:
            found['cGcGalaxyAttributeGenerator::ClassifyVoxel'] = cand[0]
    # 7. GeneratePlanetName: common caller of Markov+Translate, also calls GetInstance
    mk = a('cGcMarkovAssembler::Assemble'); tr = a('cTkLanguageManagerBase::Translate')
    gi = a('cTkLanguageManager::GetInstance')
    if mk and tr:
        cand = [c for c in (callers(mk) & callers(tr)) if c not in mapped]
        if gi:
            cand = [c for c in cand if gi in callees(c)] or cand
        if len(cand) == 1:
            found['cGcNameGenerator::GeneratePlanetName'] = cand[0]
    # 8. ctor: common caller of SolarSystemData::SetDefaults & cGcPlanet::cGcPlanet, called by Simulation::Construct
    ssd = a('cGcSolarSystemData::SetDefaults'); pl = a('cGcPlanet::cGcPlanet')
    sc = a('cGcSimulation::Construct')
    if ssd and pl:
        cand = [c for c in (callers(ssd) & callers(pl)) if c not in mapped]
        if sc:
            cand2 = [c for c in cand if c in callees(sc)]
            if cand2: cand = cand2
        if len(cand) == 1:
            found['cGcSolarSystem::cGcSolarSystem'] = cand[0]
    return side, size, A, found

if __name__ == '__main__':
    b = sys.argv[1] if len(sys.argv) > 1 else '1.38'
    side, size, A, found = build_all(b)
    print(f'== {b}: {len(found)} derived ==', file=sys.stderr)
    for k in sorted(found):
        print(f'{k} = {hex(found[k])} size={size.get(found[k])}')
