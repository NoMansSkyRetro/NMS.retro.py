import calls as C, json, os, sys, bisect
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

def modern_callee_seq(caller):
    va=M.name2va.get(caller)
    if va is None: return None
    return [(M.containing(t), M.va2name.get(M.containing(t))) for s,t in M.calls(va)]

def legacy_callee_seq(b, cva):
    ll=L(b)
    return [ll.containing(t) for s,t in ll.calls(cva)]

def find_callee_local(caller, target, build, maxgap=6):
    """Find legacy addr of target called by caller, anchoring on nearest mapped callee before target."""
    p=prop(build); rev=_rev[build]
    if caller not in p: return None,'caller unmapped'
    lc=int(p[caller]['address'],16)
    mseq=modern_callee_seq(caller)
    mnames=[nm for _,nm in mseq]
    if target not in mnames: return None,'target not called by caller (modern)'
    lseq=legacy_callee_seq(build,lc)
    # try each occurrence of target
    for it,(mc,mn) in enumerate(mseq):
        if mn!=target: continue
        # nearest preceding mapped anchor
        for ia in range(it-1,-1,-1):
            an=mseq[ia][1]
            if an and an in p:
                la=int(p[an]['address'],16)
                # count mapped-callee steps between anchor and target in modern (calls to funcs; we align by ordinal of *distinct* call positions)
                gap = it-ia
                if gap>maxgap: break
                # find anchor call in legacy, take the element gap positions after
                for j,lv in enumerate(lseq):
                    if lv==la:
                        if j+gap < len(lseq):
                            cand=lseq[j+gap]
                            return cand,f'anchor={an.split("::")[-1]} gap={gap} legacy_anchor={la:X}'
                break
    return None,'no local anchor'

def calls_target(build, cva, tva):
    for lv in legacy_callee_seq(build,cva):
        if lv==tva: return True
    return False

if __name__=='__main__':
    import sys
    what=sys.argv[1]
    if what=='local':
        caller,target=sys.argv[2],sys.argv[3]
        for b in ['1.09.1','1.13','1.24','1.38']:
            va,why=find_callee_local(caller,target,b)
            print(f'{b:8} {va and hex(va)}  ({why})')
    elif what=='mseq':
        # print modern callee names around target
        caller,target=sys.argv[2],sys.argv[3]
        ms=modern_callee_seq(caller)
        names=[nm for _,nm in ms]
        idxs=[i for i,n in enumerate(names) if n==target]
        for i in idxs:
            lo=max(0,i-5); hi=min(len(names),i+3)
            print('context:',[ (names[k].split('::')[-1] if names[k] else '?') for k in range(lo,hi)])
