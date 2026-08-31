"""V1_00 from a source def, removing fields chosen by DUMPED offsets (walk truth).
Usage: make_v100b.py <src.cs> <out.cs> <template> <nmsver> <ranges> [--split-longs] [add-anchor-name:decl ...]"""
import re,sys,json,subprocess,os
EXE=r"E:\Sync\No Man's Sky\MBINCompiler.retro\Build\Release\win-x64\MBINCompiler.exe"
env=dict(os.environ,DOTNET_ROLL_FORWARD='LatestMajor')
src,out,template,ver,ranges=sys.argv[1:6]
rest=sys.argv[6:]
split_longs='--split-longs' in rest
adds=[a.split(':',1) for a in rest if ':' in a and not a.startswith('--')]
rngs=[(int(lo,16),int(hi,16)) for lo,hi in (r.split('-') for r in ranges.split(','))]
r=subprocess.run([EXE,'dumplayout',f'--nms-version={ver}',template],capture_output=True,text=True,env=env)
j,_=json.JSONDecoder().raw_decode(r.stdout.lstrip('\ufeff'))
fields=j[template]['fields']
drop=set(); partial=[]
for f in fields:
    o,sz=f['offset'],f['size']
    if any(lo<=o and o+sz<=hi for lo,hi in rngs): drop.add(f['name'])
    elif any(o<hi and o+sz>lo for lo,hi in rngs): partial.append(f)
for p in partial: print('PARTIAL:',hex(p['offset']),hex(p['size']),p['name'])
s=open(src,encoding='utf-8-sig').read()
s=re.sub(r'namespace libMBIN\.(NMS\.\w+|V1_09_1\.Structs)','namespace libMBIN.V1_00.Structs',s)
if 'using libMBIN.NMS;' not in s: s='using libMBIN.NMS;'+chr(10)+s
removed=0
for name in drop:
    pat=re.compile(r'(\s*\[NMS\([^\)]*\)\]\s*\n)?\s*public [\w\[\]\.]+ '+re.escape(name)+r';[^\n]*\n')
    s2=pat.sub('\n',s,count=1)
    if s2==s: print('MISS:',name)
    else: removed+=1; s=s2
if split_longs:
    for m in list(re.finditer(r'^(\s*)public long (\w+);[^\n]*$',s,flags=re.M)):
        s=s.replace(m.group(0),f'{m.group(1)}public int {m.group(2)}a;\n{m.group(1)}public int {m.group(2)}b;')
for anchor,decl in adds:
    pat=re.compile(r'(^\s*public [\w\[\]\.]+ '+re.escape(anchor)+r'[ab]?;[^\n]*$)',re.M)
    s2=pat.sub(lambda m:m.group(1)+'\n        '+decl,s,count=1)
    assert s2!=s, f'anchor {anchor} missing'
    s=s2
open(out,'w').write(s)
print(f'removed {removed}/{len(drop)} fields; splits={split_longs}; adds={len(adds)}')
