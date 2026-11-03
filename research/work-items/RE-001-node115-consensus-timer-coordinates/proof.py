"""Independent static coordinate proof; never executes the captured target."""
from pathlib import Path
import hashlib, json, re, struct, subprocess
TARGET = Path('artifacts/node/115/hl-node')
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
LOCATION, PATH_VA, REFERENCE = 0x649dcf8, 4501165, 0x4eca743
START, END = 0x4eca5d0, 0x4eca82c
NAME = b'node/src/consensus/timer.rs'
class Invalid(ValueError): pass
def need(condition, message):
    if not condition: raise Invalid(message)
def layout(b):
    need(b[:6] == b'\x7fELF\x02\x01', 'ELF64 little-endian')
    phoff, shoff = struct.unpack_from('<QQ', b, 32)
    phsize, phnum, shsize, shnum, strings = struct.unpack_from('<HHHHH', b, 54)
    need(phsize == 56 and shsize == 64, 'ELF entry sizes')
    segments = [struct.unpack_from('<IIQQQQQQ', b, phoff+i*phsize) for i in range(phnum)]
    sections = [struct.unpack_from('<IIQQQQIIQQ', b, shoff+i*shsize) for i in range(shnum)]
    names = b[sections[strings][4]:sections[strings][4]+sections[strings][5]]
    def vaoff(va, size=1, executable=False):
        matches = [s[2]+va-s[3] for s in segments if s[0] == 1 and s[3] <= va and va+size <= s[3]+s[5] and (not executable or s[1]&1)]
        need(len(matches) == 1, 'unique file-backed VA')
        return matches[0]
    named = {names[s[0]:].split(b'\0',1)[0].decode():s for s in sections}
    return vaoff, sections, named

def leb(b, pos, signed=False):
    result = shift = 0
    for _ in range(10):
        v = b[pos]; pos += 1; result |= (v&127)<<shift; shift += 7
        if not v&128:
            if signed and v&64: result -= 1<<shift
            return result, pos
    raise Invalid('oversized LEB')

def frame_records(b, section):
    base, limit = section[4], section[4]+section[5]
    cies, records = {}, []
    pos = base
    while pos+4 <= limit:
        n = struct.unpack_from('<I', b, pos)[0]
        if n == 0: break
        need(n != 0xffffffff and n >= 4 and pos+4+n <= limit, 'frame length')
        ident = struct.unpack_from('<I', b, pos+4)[0]
        if ident == 0:
            q = pos+8; version = b[q]; q += 1
            need(version in (1,3), 'CIE version')
            z = b.index(0, q, pos+4+n); aug = b[q:z]; q = z+1
            _, q = leb(b,q); _,q = leb(b,q,True)
            if version == 1: q += 1
            else: _,q = leb(b,q)
            need(aug.startswith(b'z'), 'CIE augmented profile')
            alen,q = leb(b,q); stop = q+alen; encoding = None
            for c in aug[1:]:
                if c in (ord('R'),ord('L')):
                    e=b[q];q+=1
                    if c==ord('R'): encoding=e
                elif c==ord('P'):
                    e=b[q];q+=1
                    widths={0:8,2:2,3:4,4:8,10:2,11:4,12:8}
                    need((e&15) in widths, 'personality format');q+=widths[e&15]
                else: raise Invalid('CIE augmentation')
            need(q==stop and stop<=pos+4+n, 'CIE augmentation size')
            cies[pos] = encoding
        else:
            cie=pos+4-ident
            need(cie in cies, 'FDE CIE reference')
            # This packet deliberately supports only the target's pcrel/sdata4 profile.
            need(cies[cie]==0x1b, 'FDE pointer encoding')
            displacement, extent = struct.unpack_from('<ii', b, pos+8)
            lo=section[3]+(pos+8-base)+displacement
            need(extent>0, 'positive FDE extent')
            records.append((lo,lo+extent,pos,cie))
        pos+=4+n
    return records

def prove_bytes(b):
    """Low-level checks separated from digest gate for actual-byte mutation tests."""
    vaoff, sections, named = layout(b)
    relas=[]
    for s in sections:
        if s[1] != 4: continue
        need(s[9] == 24 and s[5]%24==0, 'RELA layout')
        for off in range(s[4],s[4]+s[5],24):
            loc,info,add = struct.unpack_from('<QQq',b,off)
            if loc==LOCATION: relas.append((off,info,add))
    need(len(relas)==1,'unique Location relocation')
    roff,info,add=relas[0]
    need(info==8 and add==PATH_VA,'RELATIVE symbol-zero path relocation')
    off=vaoff(LOCATION,24)
    ptr,length,line,col=struct.unpack_from('<QQII',b,off)
    need(ptr in (0,PATH_VA) and (length,line,col)==(len(NAME),17,30),'Location layout')
    poff=vaoff(PATH_VA,len(NAME))
    need(b[poff:poff+len(NAME)]==NAME,'source path')
    ref=vaoff(REFERENCE,7,True)
    ins=b[ref:ref+7]
    need(ins[:3]==b'\x48\x8d\x0d','RIP-relative LEA opcode')
    need(REFERENCE+7+struct.unpack_from('<i',ins,3)[0]==LOCATION,'LEA displacement')
    frames=frame_records(b,named['.eh_frame'])
    containing=[r for r in frames if r[0]<=REFERENCE<r[1]]
    need(len(containing)==1 and containing[0][:2]==(START,END),'unique containing FDE')
    _,_,fde,cie=containing[0]
    codeoff=vaoff(START,END-START,True)
    return dict(location_va=LOCATION,location_offset=off,path_va=PATH_VA,path_offset=poff,
                path=NAME.decode(),line=17,column=30,relocation_offset=roff,
                reference_va=REFERENCE,reference_offset=ref,instruction_hex=ins.hex(),
                fde_start=START,fde_end=END,fde_offset=fde,cie_offset=cie,
                extent_bytes=END-START,extent_sha256=hashlib.sha256(b[codeoff:codeoff+END-START]).hexdigest())

def corroborate_native(native,result):
    lines=[line for line in native.splitlines() if re.match(r'\s*'+format(REFERENCE,'x')+':',line)]
    need(len(lines)==1,'instruction alignment from FDE start')
    match=re.match(r'\s*[0-9a-f]+:\s*((?:[0-9a-f]{2} )+)',lines[0])
    need(match is not None and bytes.fromhex(match[1])==bytes.fromhex(result['instruction_hex']) and 'lea' in lines[0], 'native instruction bytes')

def authenticate(b):
    need(len(b)==SIZE and hashlib.sha256(b).hexdigest()==SHA256,'target identity')

def prove(target=TARGET):
    b=Path(target).read_bytes()
    authenticate(b)
    result=prove_bytes(b)
    cmd=['objdump','-d',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(target)]
    native=subprocess.check_output(cmd,text=True)
    corroborate_native(native,result)
    proc=subprocess.Popen(['readelf','--debug-dump=frames',str(target)],stdout=subprocess.PIPE,text=True)
    matches=[]
    for line in proc.stdout:
        m=re.search(r'FDE .*pc=([0-9a-f]+)\.\.([0-9a-f]+)',line)
        if m and int(m[1],16)<=REFERENCE<int(m[2],16): matches.append(tuple(int(x,16) for x in m.groups()))
    proc.stdout.close()
    need(proc.wait()==0 and matches==[(START,END)],'GNU FDE corroboration')
    return dict(target=str(target),sha256=SHA256,bytes=SIZE,observation=result,
                tools={t:subprocess.check_output([t,'--version'],text=True).splitlines()[0] for t in ('objdump','readelf')})
if __name__=='__main__': print(json.dumps(prove(),indent=2))
