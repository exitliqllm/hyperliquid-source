"""Target-grounded coordinate checks and corruptions, not behavioral equivalence."""
from pathlib import Path
import importlib.util
import struct
import unittest
ROOT=Path(__file__).resolve().parents[1]
HELPER=ROOT/'research/work-items/RE-001-node115-consensus-timer-coordinates/proof.py'
spec=importlib.util.spec_from_file_location('timer_coordinate_proof',HELPER)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class TimerCoordinates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b=(ROOT/p.TARGET).read_bytes()
        cls.o=p.prove_bytes(cls.b)
    def reject(self,offset,value):
        b=bytearray(self.b);b[offset:offset+len(value)]=value
        with self.assertRaises((p.Invalid,ValueError,struct.error)): p.prove_bytes(b)
    def test_authenticated_native_proof(self):
        r=p.prove(ROOT/p.TARGET)
        self.assertEqual(r['observation'],self.o)
    def test_digest_rejects_changed_target(self):
        changed=bytearray(self.b);changed[-1]^=1
        with self.assertRaises(p.Invalid): p.authenticate(changed)
    def test_identity_rejects_truncation(self):
        with self.assertRaises(p.Invalid): p.authenticate(self.b[:-1])
    def test_duplicate_relocation(self):
        at=self.o['relocation_offset']
        self.reject(at+24,self.b[at:at+24])
    def test_native_reference_missing(self):
        with self.assertRaises(p.Invalid): p.corroborate_native('',self.o)
    def test_native_wrong_boundary(self):
        line=' 4eca744:\t48 8d 0d ae 35 5d 01 \tlea location'
        with self.assertRaises(p.Invalid): p.corroborate_native(line,self.o)
    def test_path_corruption(self): self.reject(self.o['path_offset'],b'X')
    def test_location_length(self): self.reject(self.o['location_offset']+8,struct.pack('<Q',1))
    def test_location_line(self): self.reject(self.o['location_offset']+16,struct.pack('<I',18))
    def test_location_column(self): self.reject(self.o['location_offset']+20,struct.pack('<I',31))
    def test_relocation_type(self): self.reject(self.o['relocation_offset']+8,struct.pack('<Q',1))
    def test_relocation_addend(self): self.reject(self.o['relocation_offset']+16,struct.pack('<q',p.PATH_VA+1))
    def test_missing_relocation(self): self.reject(self.o['relocation_offset'],struct.pack('<Q',p.LOCATION+8))
    def test_lea_opcode(self): self.reject(self.o['reference_offset'],b'\x90')
    def test_lea_displacement(self): self.reject(self.o['reference_offset']+3,struct.pack('<i',0))
    def test_fde_range(self): self.reject(self.o['fde_offset']+12,struct.pack('<i',1))
    def test_fde_cie_reference(self): self.reject(self.o['fde_offset']+4,struct.pack('<I',1))
if __name__=='__main__': unittest.main()
