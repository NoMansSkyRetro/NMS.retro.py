"""Ordered call-target extraction from raw .text bytes, for any build or modern 4.13."""
import sys, json, struct, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import Binary, STATIC_BASE

EXE_413 = r"E:\AI_NMS_DISASM\NMS413_PDBAGENT\original_exe_lib_exp_pdb\NMS.exe"
REF_413 = r"E:\AI_NMS_DISASM\NMS1091_GHIDRA_ANALYSIS\reference_symbol_db.json"

def parse_sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    out = []
    for o in range(pe + 24 + opt, pe + 24 + opt + nsec * 40, 40):
        name = data[o:o+8].rstrip(b"\0").decode()
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, o+8)
        out.append((name, va, vsize, raw, rsize))
    return out

def text_of(data, sections):
    t = next(s for s in sections if s[0]=='.text')
    return t[3], STATIC_BASE+t[1], t[4]

def ordered_calls(data, text_raw, text_va, va, size):
    start_off = text_raw + (va - text_va)
    out=[]; end = start_off + size; p = start_off
    while p < end-4:
        b0 = data[p]
        if b0==0xE8 or b0==0xE9:
            rel = struct.unpack_from('<i', data, p+1)[0]
            site_va = text_va + (p - text_raw)
            out.append((site_va, site_va + 5 + rel)); p += 5
        else: p += 1
    return out

class Modern:
    def __init__(self):
        self.data=open(EXE_413,'rb').read()
        self.sections=parse_sections(self.data)
        self.text_raw,self.text_va,self.text_size=text_of(self.data,self.sections)
        ref=json.load(open(REF_413))
        self.name2va={}; self.va2name={}; self.va2size={}
        for f in ref['functions']:
            va=STATIC_BASE+f['rva']; nm=f.get('undecorated_name') or f['name']
            self.name2va.setdefault(nm,va); self.va2name[va]=nm; self.va2size[va]=f.get('length') or 0
        self.starts=sorted(self.va2name)
    def size(self,va): return self.va2size.get(va,0)
    def calls(self,va):
        sz=self.va2size.get(va,0) or 0x4000
        return ordered_calls(self.data,self.text_raw,self.text_va,va,sz)
    def containing(self,tgt):
        import bisect
        i=bisect.bisect_right(self.starts,tgt)-1
        if i>=0:
            s=self.starts[i]
            if s<=tgt<s+(self.va2size.get(s,0) or 0): return s
        return None

class Legacy:
    def __init__(self,build):
        self.b=Binary(build)
        self.sections=[(s.name,s.virtual_address,s.virtual_size,s.raw_offset,s.raw_size) for s in self.b.sections]
        self.text_raw,self.text_va,self.text_size=text_of(self.b.data,self.sections)
        rows=self.b.db.execute("SELECT address,size,name FROM decompilations").fetchall()
        self.va2size={a:s for a,s,n in rows}; self.va2name={a:n for a,s,n in rows}
        self.starts=sorted(self.va2size)
    def size(self,va): return self.va2size.get(va)
    def function_at(self,va): return self.b.function_at(va)
    def calls(self,va):
        sz=self.va2size.get(va)
        if not sz: return []
        return ordered_calls(self.b.data,self.text_raw,self.text_va,va,sz)
    def containing(self,tgt):
        import bisect
        i=bisect.bisect_right(self.starts,tgt)-1
        if i>=0:
            s=self.starts[i]
            if s<=tgt<s+(self.va2size.get(s,0) or 0): return s
        return None
