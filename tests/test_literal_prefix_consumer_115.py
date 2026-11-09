import copy,importlib.util,json,unittest
from pathlib import Path
P=Path(__file__).resolve().parents[1]/'research/work-items/RE-015-literal-prefix-consumer-115'
spec=importlib.util.spec_from_file_location('consumer',P/'verify_consumer.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ConsumerEvidence(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.actual=m.derive();cls.saved=json.loads((P/'verified-consumer.json').read_text())
 def test_authentic_target(self):
  self.assertTrue(m.verify(self.saved,self.actual));self.assertEqual(self.actual['destination_va'],'0x440f30');self.assertEqual(self.actual['literal_token_hex'],'686c2d6e6f6465');self.assertEqual(self.actual['frames'],[['0x3ae32c','0x39672c','0x15a20a0','0x15a37fe']])
 def test_corruption_controls(self):
  changes={'target_sha256':'0'*64,'target_bytes':0,'site_va':'0x15a230c','site_file_offset':'0x15a130c','site_hex':'00'*7,'destination_va':'0x440f36','literal_va':'0x440f30','literal_token_hex':'00'*7,'entry_13_bytes_hex':'00'*13,'call_va':'0x15a2323','call_hex':'00'*6,'call_slot_va':'0x64df6e9','relative_writers':[],'frames':[],'captured_code_executed':True}
  for key,value in changes.items():
   with self.subTest(field=key):
    changed=copy.deepcopy(self.saved);changed[key]=value
    with self.assertRaises(ValueError):m.verify(changed,self.actual)
if __name__=='__main__':unittest.main(verbosity=2)
