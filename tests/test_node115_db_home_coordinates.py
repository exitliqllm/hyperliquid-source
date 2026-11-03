"""Real capture binding and counterfactual byte controls; never run the node."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('db_home_coordinates', ROOT / 'tools/node115_db_home_coordinates.py')
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)


class DbHomeCoordinateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ROOT / proof.TARGET
        cls.data = cls.target.read_bytes()
        cls.result = proof.analyse(cls.target)
        cls.binding = proof.recover(cls.data)

    def mutated(self, offset, replacement):
        data = bytearray(self.data)
        data[offset:offset + len(replacement)] = replacement
        with self.assertRaises(ValueError):
            proof.recover(data)

    def test_real_target_native_boundary_and_fde(self):
        self.assertEqual(self.result['target_sha256'], proof.SHA256)
        self.assertEqual(self.result['fde_start'], '0x44699c0')
        self.assertEqual(self.result['fde_end'], '0x4469bd8')
        self.assertEqual(self.result['fde_bytes'], 536)
        self.assertEqual(self.result['instruction_bytes'], '488d15f51d0202')

    def test_real_source_and_relocation(self):
        self.assertEqual(self.binding['source_path'], 'db/src/db_home.rs')
        self.assertEqual((self.binding['line'], self.binding['column']), (85, 13))
        self.assertEqual(self.binding['location_va'], '0x648b960')
        self.assertEqual(self.binding['relocation_info'], 8)

    def test_opcode_control(self):
        self.mutated(int(self.binding['instruction_file_offset'], 16), b'\x49')

    def test_displacement_control(self):
        self.mutated(int(self.binding['instruction_file_offset'], 16) + 3, b'\xf4')

    def test_relocation_offset_control(self):
        self.mutated(proof.RELA_OFFSET, struct.pack('<Q', proof.LOCATION + 8))

    def test_relocation_type_control(self):
        self.mutated(proof.RELA_OFFSET + 8, struct.pack('<Q', 1))

    def test_relocation_addend_control(self):
        self.mutated(proof.RELA_OFFSET + 16, struct.pack('<q', 0x448052))

    def test_source_pointer_control(self):
        self.mutated(int(self.binding['location_file_offset'], 16), struct.pack('<Q', 1))

    def test_source_length_control(self):
        self.mutated(int(self.binding['location_file_offset'], 16) + 8, struct.pack('<Q', 16))

    def test_source_line_control(self):
        self.mutated(int(self.binding['location_file_offset'], 16) + 16, struct.pack('<I', 86))

    def test_source_column_control(self):
        self.mutated(int(self.binding['location_file_offset'], 16) + 20, struct.pack('<I', 14))

    def test_source_bytes_control(self):
        self.mutated(int(self.binding['source_file_offset'], 16), b'x')

    def test_truncated_elf(self):
        with self.assertRaises(ValueError):
            proof.recover(self.data[:64])

    def test_wrong_identity_before_native_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / 'bad'
            bad.write_bytes(b'not a target')
            with patch.object(proof.subprocess, 'check_output') as native:
                with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                    proof.analyse(bad)
                native.assert_not_called()

    def test_same_size_wrong_digest_before_native_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / 'bad'
            data = bytearray(self.data)
            data[-1] ^= 1
            bad.write_bytes(data)
            with patch.object(proof.subprocess, 'check_output') as native:
                with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                    proof.analyse(bad)
                native.assert_not_called()


if __name__ == '__main__':
    unittest.main()
