"""Verify one authenticated static xref; no captured execution or network."""
from pathlib import Path
import hashlib,json,re,struct,subprocess
DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
def derive(path=Path('artifacts/node/115/hl-node')):
 b=path.read_bytes()
 if hashlib.sha256(b).hexdigest()!=DIGEST:raise ValueError('target digest')
 phoff=struct.unpack_from('<Q',b,32)[0];ps,pn=struct.unpack_from('<HH',b,54)
 seg=[struct.unpack_from('<IIQQQQQQ',b,phoff+i*ps) for i in range(pn)]
 def get(va,n):
  offsets=[s[2]+va-s[3] for s in seg if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]]
  if len(offsets)!=1:raise ValueError('PT_LOAD mapping')
  o=offsets[0];return o,b[o:o+n]
 site=0x15a230b;o,raw=get(site,7)
 if raw[:3]!=bytes.fromhex('488d35'):raise ValueError('LEA opcode')
 destination=site+7+struct.unpack_from('<i',raw,3)[0]
 literal_va=0x440f36;_,token=get(literal_va,7)
 _,entry=get(destination,13)
 # Decode the subsequent indirect call independently of the disassembler.
 call_va=0x15a2322;_,call=get(call_va,6)
 if call[:2]!=bytes.fromhex('ff15'):raise ValueError('call opcode')
 call_slot=call_va+6+struct.unpack_from('<i',call,2)[0]
 sho=struct.unpack_from('<Q',b,40)[0];ss,sn,si=struct.unpack_from('<HHH',b,58)
 sections=[struct.unpack_from('<IIQQQQIIQQ',b,sho+i*ss) for i in range(sn)]
 names=b[sections[si][4]:sections[si][4]+sections[si][5]]
 rela=next(s for s in sections if names[s[0]:].split(b'\0',1)[0]==b'.rela.dyn')
 slots={call_slot,0x64e0a98};relocations=[]
 for pos in range(rela[4],rela[4]+rela[5],rela[9]):
  va,info,addend=struct.unpack_from('<QQq',b,pos)
  if va in slots:relocations.append([hex(va),hex(pos),info&0xffffffff,info>>32,hex(addend)])
 frame_text=subprocess.check_output(['readelf','--debug-dump=frames',str(path)],text=True)
 frames=[]
 for line in frame_text.splitlines():
  m=re.search(r'^([0-9a-f]+).*FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)',line)
  if m and int(m[3],16)<=site<int(m[4],16):frames.append([hex(int(m[x],16)) for x in (1,2,3,4)])
 return {'target_sha256':DIGEST,'target_bytes':len(b),'site_va':hex(site),'site_file_offset':hex(o),'site_hex':raw.hex(),'destination_va':hex(destination),'literal_va':hex(literal_va),'literal_token_hex':token.hex(),'entry_13_bytes_hex':entry.hex(),'call_va':hex(call_va),'call_hex':call.hex(),'call_slot_va':hex(call_slot),'relative_writers':relocations,'frames':frames,'captured_code_executed':False}
def verify(record,actual):
 if record!=actual:raise ValueError('saved evidence differs from authenticated derivation')
 return True
if __name__=='__main__':
 actual=derive();out=Path(__file__).with_name('verified-consumer.json')
 if out.exists():verify(json.loads(out.read_text()),actual)
 else:out.write_text(json.dumps(actual,indent=2,sort_keys=True)+'\n')
 print(json.dumps(actual,indent=2,sort_keys=True))
