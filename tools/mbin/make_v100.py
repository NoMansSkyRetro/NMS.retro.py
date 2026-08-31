"""Generate a V1_00 def from a base def by removing fields at given 1.09.1 offsets.
Usage: make_v100.py <base.cs> <out.cs> <remove-ranges e.g. 0x4-0x2C,0x40-0x44> [--add off:decl ...]
Fields are matched by their 'offset: 0xNN' comment (or 'offset: N' decimal)."""
import re,sys
src,out,ranges=sys.argv[1],sys.argv[2],sys.argv[3]
adds=[a.split(':',1) for a in sys.argv[4:]]
rngs=[]
for r in ranges.split(','):
    lo,hi=r.split('-')
    rngs.append((int(lo,16),int(hi,16)))
s=open(src,encoding='utf-8-sig').read()
s=re.sub(r'namespace libMBIN\.NMS\.\w+','namespace libMBIN.V1_00.Structs',s)
if 'using libMBIN.NMS;' not in s:
    s='using libMBIN.NMS;' + chr(10) + s
lines=s.split('\n')
outl=[];removed=[];i=0
def foff(line):
    m=re.search(r'offset: (0x[0-9A-Fa-f]+|\d+), sz: (0x[0-9A-Fa-f]+|\d+)',line)
    if not m: return None
    return int(m.group(1),0),int(m.group(2),0)
while i<len(lines):
    line=lines[i]
    om=foff(line)
    if om and 'public' in line:
        o,sz=om
        drop=any(lo<=o and o+sz<=hi for lo,hi in rngs)
        part=any(o<hi and o+sz>lo and not(lo<=o and o+sz<=hi) for lo,hi in rngs)
        if part: print(f'WARN partial overlap at {o:#x}+{sz:#x}: {line.strip()[:80]}')
        if drop:
            removed.append((o,sz))
            # also drop a preceding attribute line if it exists
            if outl and outl[-1].strip().startswith('[NMS('): outl.pop()
            i+=1; continue
    outl.append(line); i+=1
s='\n'.join(outl)
for off,decl in adds:
    # insert decl after the field whose offset comment matches off
    pat=re.compile(r'(^.*offset: '+re.escape(off)+r',[^\n]*$)',re.M)
    s2=pat.sub(lambda m: m.group(1)+'\n        '+decl, s, count=1)
    assert s2!=s, f'add anchor {off} not found'
    s=s2
open(out,'w').write(s)
tot=sum(sz for _,sz in removed)
print(f'removed {len(removed)} fields totalling {tot:#x} bytes; adds: {len(adds)}')
