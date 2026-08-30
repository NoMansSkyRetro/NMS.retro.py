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

def check_map(names):
    for b in ['1.09.1','1.13','1.24','1.38']:
        p=prop(b)
        row=' '.join(f'{n.split("::")[-1]}={"Y" if n in p else "-"}' for n in names)
        print(b,row)

def call_before(caller, follower, build):
    """Return the internal-callee immediately before the call to `follower` (mapped) in legacy caller."""
    p=prop(build); rev=_rev[build]; ll=L(build)
    if caller not in p or follower not in p: return None,'unmapped'
    lc=int(p[caller]['address'],16); fol=int(p[follower]['address'],16)
    seq=[ll.containing(t) for s,t in ll.calls(lc)]
    # internal only
    internal=[x for x in seq if x is not None]
    for i,x in enumerate(internal):
        if x==fol and i>0:
            # walk back to previous DISTINCT internal that isn't the caller/self
            j=i-1
            while j>=0 and internal[j] in (lc,fol):
                j-=1
            if j>=0:
                return internal[j],f'before {follower.split("::")[-1]} (idx {i})'
    return None,'follower not called'

if __name__=='__main__':
    cmd=sys.argv[1]
    if cmd=='map':
        check_map(sys.argv[2:])
    elif cmd=='before':
        caller,follower=sys.argv[2],sys.argv[3]
        for b in ['1.09.1','1.13','1.24','1.38']:
            va,why=call_before(caller,follower,b)
            print(f'{b:8} {va and hex(va)}  size={L(b).size(va) if va else None}  ({why})')
