"""Synthetic checks for the independent SELF auxiliary-section classifier."""
import runpy
import struct
import unittest
from pathlib import Path


class OpaqueSelfSections(unittest.TestCase):
    classifier = staticmethod(runpy.run_path(
        str(Path(__file__).with_name('ps3-liberation.py'))
    )['opaque_self_sections'])

    def classify(self, data, header, records, table_authenticated=True):
        return self.classifier(data, header, records, lambda s, p: table_authenticated)

    def fixture(self):
        data = bytearray(0x400)
        elf, phdr, shdr = 0x70, 0xb0, 0x300
        struct.pack_into('>I', data, 12, 0x1e0)
        struct.pack_into('>QQ', data, 16, 0x200, 0x4000)
        struct.pack_into('>QQQ', data, 48, elf, phdr, shdr)
        struct.pack_into('>Q', data, 72, 0xe8)
        struct.pack_into('>QQ', data, 0xe8, 0x200, 32)
        data[elf:elf+7] = b'\x7fELF\x02\x02\x01'
        struct.pack_into('>HH', data, elf+16, 2, 21)
        struct.pack_into('>I', data, elf+20, 1)
        struct.pack_into('>QQ', data, elf+32, 64, 0x3000)
        struct.pack_into('>H', data, elf+52, 64)
        struct.pack_into('>HHHH', data, elf+54, 56, 1, 64, 3)
        struct.pack_into('>IIQQQQQQ', data, phdr, 1, 5, 0x1000, 0, 0, 32, 32, 16)
        struct.pack_into('>IIQQQQIIQQ', data, shdr+128,
                         0, 1, 0, 0, 0x2000, 17, 0, 0, 1, 0)

        def record(offset, size, kind, index):
            return bytearray(struct.pack('>QQIIIIIIII',
                                        offset, size, kind, index, 2, 0, 1, 0, 0, 1))

        records = [record(0x200, 32, 2, 0), record(0x240, 17, 3, 2),
                   record(shdr, 3*64, 1, 0)]
        return data, records

    def test_auxiliary_is_classified_without_using_payload_contents(self):
        data, records = self.fixture()
        self.assertEqual(self.classify(data, data[:0x200], records), {1, 2})
        data[0x240:0x251] = b'opaque key bytes!'
        self.assertEqual(self.classify(data, data[:0x200], records), {1, 2})

    def test_untrusted_table_does_not_exempt_auxiliary_payload(self):
        data, records = self.fixture()
        self.assertEqual(self.classify(data, data[:0x200], records, False), {2})

    def test_untrusted_table_without_type_three_payload(self):
        data, records = self.fixture()
        records = [records[0], records[2]]
        self.assertEqual(self.classify(data, data[:0x200], records, False), {1})

    def test_runtime_and_ambiguous_sections_get_no_exemption(self):
        mutations = [
            (lambda d, r: struct.pack_into('>Q', d, 0x388, 2), {2}),  # SHF_ALLOC
            (lambda d, r: struct.pack_into('>Q', d, 0x390, 1), {2}),  # runtime address
            (lambda d, r: struct.pack_into('>Q', d, 0x398, 0x1000), {2}),  # ELF overlap
            (lambda d, r: struct.pack_into('>Q', d, 0x3a0, 18), {2}),  # wrong size
            (lambda d, r: struct.pack_into('>Q', r[1], 0, 0x200), set()),  # SELF overlap
            (lambda d, r: struct.pack_into('>I', r[1], 20, 3), {2}),  # bad section index
            (lambda d, r: struct.pack_into('>I', r[1], 32, 3), {2}),  # encrypted
            (lambda d, r: struct.pack_into('>I', r[1], 44, 2), {2}),  # compressed
            (lambda d, r: struct.pack_into('>Q', r[2], 8, 64), set()),  # no matching table
            (lambda d, r: struct.pack_into('>H', d, 0x80, 1), set()),  # not ET_EXEC
            (lambda d, r: struct.pack_into('>Q', d, 0xe8, 0x300), set()),  # SELF segment overlap
        ]
        for mutate, expected in mutations:
            with self.subTest(mutate=mutate):
                data, records = self.fixture()
                mutate(data, records)
                self.assertEqual(self.classify(data, data[:0x200], records), expected)

    def test_truncated_table_is_rejected(self):
        data, records = self.fixture()
        with self.assertRaises(AssertionError):
            self.classify(data[:0x380], data[:0x200], records)


if __name__ == '__main__':
    unittest.main()
