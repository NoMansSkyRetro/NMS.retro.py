import calls as C, json, os, sys
OUTDIR=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'out')
M=C.Modern()
_leg={}; _prop={}; _rev={}
def prop(b):
    if b not in _prop:
        _prop[b]=json.load(open(os.path.join(OUTDIR,f'propagated_{b}.json')))
        _rev[b]={int(v['address'],16):k for k,v in _prop[b].items()}
    return _prop[b]
def L(b):
    if b not in _leg: _leg[b]=C.Legacy(b)
    return _leg[b]

def modern_callee_names(mva):
    return set(filter(None,(M.va2name.get(M.containing(t)) for s,t in M.calls(mva))))
def legacy_callee_names(b,lva):
    prop(b); rev=_rev[b]; ll=L(b)
    return set(filter(None,(rev.get(ll.containing(t)) for s,t in ll.calls(lva))))

def rank_callees_of(caller, target_modern, build, topn=8):
    """Score each distinct internal callee of legacy `caller` by callee-name overlap w/ modern target."""
    p=prop(build)
    if caller not in p:
        print(build,'caller unmapped'); return
    lc=int(p[caller]['address'],16)
    ll=L(build)
    mtn=modern_callee_names(M.name2va[target_modern])
    seen=set(); scored=[]
    for s,t in ll.calls(lc):
        cv=ll.containing(t)
        if not cv or cv in seen: continue
        seen.add(cv)
        ln=legacy_callee_names(build,cv)
        sh=mtn & ln
        scored.append((len(sh),cv,ll.size(cv),sorted(x.split('::')[-1] for x in sh)))
    scored.sort(reverse=True)
    print(f'== {build} :: callees of {caller} ranked vs {target_modern} (modern {len(mtn)} named callees) ==')
    for sc,cv,sz,sh in scored[:topn]:
        print(f'  {cv:X} size={sz} shared={sc} {sh}')

if __name__=='__main__':
    caller=sys.argv[1]; target=sys.argv[2]
    for b in ['1.09.1','1.13','1.24','1.38']:
        rank_callees_of(caller,target,b)
