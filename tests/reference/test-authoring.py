#!/usr/bin/env python3
"""Keyless verifier regression tests, not independent crypto or writer evidence."""
import hashlib
import importlib.util
import pathlib
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("authoring", pathlib.Path(__file__).with_name("check-authoring.py"))
AUTHORING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHORING)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="authoring-verifier-")
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / "synthetic.pkg"
        # Original opaque test records. No valid RSA, license, SFO or PFS contents.
        self.data = bytearray(0x100000)
        self.data[:4] = b"\x7fCNT"
        self.put32(0x10, 13)
        struct.pack_into(">HH", self.data, 0x14, 6, 13)
        self.put32(0x18, 0x2A80)
        self.put32(0x1C, 0xDC0)
        self.put64(0x20, 0x2000)
        self.put64(0x28, 0x7E000)
        self.put32(0x74, 0x1A)
        self.put32(0x78, 0x0A000000)
        self.put32(0x7C, 0x80000)
        self.put64(0x410, 0x80000)
        self.put64(0x418, 0x80000)
        self.put64(0x428, len(self.data))
        self.put64(0x430, len(self.data))
        # Explicit fixture layout, not production writer allocation code.
        layout = {
            1: (0x2C20, 416, 0x40000000, 0),
            0x10: (0x2000, 0x800, 0x60000000, 0),
            0x20: (0x2800, 0x100, 0xE0000000, 0x3000),
            0x80: (0x2900, 0x180, 0x60000000, 0),
            0x100: (0x2A80, 416, 0x60000000, 0),
            0x200: (0x2DC0, 1, 0x40000000, 0),
            0x400: (0x2DD0, 0x400, 0x80000000, 0x3000),
            0x401: (0x31D0, 0x200, 0x80000000, 0x2000),
            0x409: (0x33D0, 0x2000, 0, 0),
            0x1000: (0x53D0, 16, 0, 0),
            0x1001: (0x53E0, 16, 0, 0),
            0x1002: (0x53F0, 64, 0, 0),
            0x1003: (0x5430, 16, 0, 0),
        }
        self.records = {}
        for index, (entry_id, (offset, length, flags1, flags2)) in enumerate(layout.items()):
            position = 0x2A80 + index * 32
            struct.pack_into(">6I", self.data, position, entry_id, 0, flags1, flags2, offset, length)
            self.records[entry_id] = (index, offset, length)
        self.seal()

    def put32(self, offset, value):
        struct.pack_into(">I", self.data, offset, value)

    def put64(self, offset, value):
        struct.pack_into(">Q", self.data, offset, value)

    def sha(self, offset, size):
        return hashlib.sha256(self.data[offset:offset + size]).digest()

    def seal_header(self):
        self.data[0xFE0:0x1000] = self.sha(0, 0xFE0)

    def seal_body(self):
        self.data[0x160:0x180] = self.sha(0x2000, 0x7E000)
        self.seal_header()

    def seal(self, playgo=True):
        if playgo:
            for block in range(8, 16):
                self.data[0x53F0 + block * 4:0x53F4 + block * 4] = self.sha(block * 65536, 65536)[:4]
        for index, offset, size in self.records.values():
            if index:
                self.data[0x2C20 + index * 32:0x2C40 + index * 32] = self.sha(offset, size)
        self.data[0x140:0x160] = self.sha(0x2C20, 416)
        for slot, ids in [(0x100, (0x10, 0x20, 0x80, 0x100, 1)),
                          (0x120, (0x10, 0x20, 0x80, 0x100))]:
            chunks = []
            for entry_id in ids:
                _, offset, size = self.records[entry_id]
                if slot == 0x120 and entry_id == 0x100:
                    size = 6 * 32
                chunks.append(self.data[offset:offset + size])
            self.data[slot:slot + 32] = hashlib.sha256(b"".join(chunks)).digest()
        self.data[0x440:0x460] = self.sha(0x80000, 0x80000)
        self.data[0x460:0x480] = self.sha(0x80000, 65536)
        self.seal_body()

    def verify(self):
        self.path.write_bytes(self.data)
        return AUTHORING.integrity(self.path)

    def reject(self, expected):
        if expected not in ("out-of-range region", "unexpected synthetic entry count",
                            "not a bounded synthetic package") and not expected.startswith("integrity mismatch: "):
            expected = "integrity mismatch: " + expected
        with self.assertRaises(ValueError) as caught:
            self.verify()
        self.assertEqual(str(caught.exception), expected)

    def test_valid_opaque_fixture(self):
        self.assertIn("SC2", self.verify())

    def test_structural_corruptions(self):
        original = self.data[:]
        cases = [
            ("mirrored entry count", lambda: self.put32(0x14, 6 << 16 | 12)),
            ("unexpected synthetic entry count", lambda: self.put32(0x10, 65)),
            ("SC entry count", lambda: self.put32(0x14, 4 << 16 | 13)),
            ("out-of-range region", lambda: self.put64(0x28, 2**64 - 1)),
            ("body/PFS boundary", lambda: self.put64(0x28, 0x7D000)),
            ("PFS alignment", lambda: (self.put64(0x410, 0x7FFFF), self.put64(0x28, 0x7DFFF))),
            ("PFS block length", lambda: self.put64(0x418, 65535)),
            ("PFS end", lambda: self.put64(0x418, 0x70000)),
            ("METAS table location/length", lambda: self.put32(0x2A80 + 4 * 32 + 20, 400)),
            ("unique sorted entry IDs", lambda: self.put32(0x2AA0, 1)),
            ("required base entries", lambda: self.put32(0x2A80 + 12 * 32, 0x1004)),
            ("entry alignment", lambda: self.put32(0x2A80 + 9 * 32 + 16, 0x53D1)),
            ("entry in body", lambda: self.put32(0x2A80 + 9 * 32 + 16, 0x1000)),
            ("out-of-range region", lambda: self.put32(0x2A80 + 9 * 32 + 20, 0xFFFFFFFF)),
            ("nonoverlapping entries", lambda: self.put32(0x2A80 + 9 * 32 + 16, 0x53C0)),
            ("physical system order", lambda: (self.put32(0x2AA0 + 16, 0x2800),
                                                self.put32(0x2AC0 + 16, 0x2000))),
            ("record reserved bytes", lambda: self.put32(0x2A80 + 24, 1)),
            ("entry 401 flags", lambda: self.put32(0x2A80 + 7 * 32 + 12, 0x3000)),
            ("entry name boundary", lambda: self.put32(0x2A80 + 4, 1)),
            ("initial empty entry name", lambda: self.data.__setitem__(0x2DC0, 65)),
            ("terminated ASCII entry name", lambda: (
                self.put32(0x2A80 + 5 * 32 + 20, 2),
                self.put32(0x2A80 + 4, 1), self.data.__setitem__(0x2DC1, 65))),
            ("PlayGo digest length", lambda: (
                self.put32(0x2A80 + 11 * 32 + 20, 60), self.seal())),
        ]
        for expected, change in cases:
            with self.subTest(expected=expected):
                self.data = original[:]
                change()
                self.reject(expected)

    def test_digest_corruptions(self):
        original = self.data[:]
        for expected, offset, repair in [
            ("header", 0x80, None),
            ("body", 0x7FFFF, None),
            ("PFS first block", 0x80000, None),
            ("PFS image", 0xFFFFF, None),
            ("digest self slot", 0x2C20, self.seal_body),
            ("digest table", 0x2C40, self.seal_body),
            ("entry 20", 0x2800, self.seal_body),
            ("SC1", 0x100, self.seal_header),
            ("SC2", 0x120, self.seal_header),
        ]:
            with self.subTest(expected=expected):
                self.data = original[:]
                self.data[offset] ^= 1
                if repair:
                    repair()
                self.reject("integrity mismatch: " + expected)

    def test_playgo_coverage(self):
        # Repair all general hashes so stale package-relative PlayGo slots alone fail.
        self.data[0xFFFFF] ^= 1
        self.seal(playgo=False)
        self.reject("PlayGo PFS block")

    def test_playgo_pre_pfs_slots(self):
        self.data[0x53F0] = 1
        self.seal()
        self.reject("PlayGo pre-PFS slots")

    def test_truncated_package(self):
        del self.data[-1:]
        self.reject("not a bounded synthetic package")


if __name__ == "__main__":
    unittest.main()
