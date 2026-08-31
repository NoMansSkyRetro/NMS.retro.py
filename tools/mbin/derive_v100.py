"""Map rc1-vs-1.09.1 insert ranges onto the base def's dumped field layout."""
import json,subprocess,sys,os,difflib,struct
EXE=r"E:\Sync\No Man's Sky\MBINCompiler.retro\Build\Release\win-x64\MBINCompiler.exe"
env=dict(os.environ,DOTNET_ROLL_FORWARD='LatestMajor')
name,template=sys.argv[1],sys.argv[2]
a=open(f'out/verify/rc1/mbin/{name}','rb').read()[0x60:]
b=open(f'out/verify/1_09_1/mbin/{name}','rb').read()[0x60:]
def words(d): return [d[i:i+4] for i in range(0,len(d)-len(d)%4,4)]
wa,wb=words(a),words(b)
ops=[o for o in difflib.SequenceMatcher(a=wa,b=wb,autojunk=False).get_opcodes() if o[0]!='equal']
r=subprocess.run([EXE,'dumplayout','--nms-version=1.09.1',template],capture_output=True,text=True,env=env)
j,_=json.JSONDecoder().raw_decode(r.stdout.lstrip('\ufeff'))
t=j.get(template)
fields=t['fields'] if t else []
def cover(lo,hi):
    out=[]
    for f in fields:
        if f['offset']<hi and f['offset']+f['size']>lo:
            tag='EXACT' if lo<=f['offset'] and f['offset']+f['size']<=hi else 'part'
            out.append(f"{f['offset']:#x}+{f['size']:x} {f['type']} {f['name']} [{tag}]")
    return out
print(f"rc1 {len(a):#x}  1.09.1 {len(b):#x}  ({len(a)-len(b):+#x});  dump size {t['size']:#x}" if t else f"TEMPLATE {template} NOT IN DUMP")
for tag,i1,i2,j1,j2 in ops:
    la,lb=(i2-i1)*4,(j2-j1)*4
    kind='VAL' if tag=='replace' and la==lb else tag.upper()
    print(f"{kind:7} rc1[{i1*4:#x}:{i2*4:#x}]({la:#x}) 1091[{j1*4:#x}:{j2*4:#x}]({lb:#x})")
    if kind!='VAL' and t:
        for line in cover(j1*4,j2*4): print('   ',line)
