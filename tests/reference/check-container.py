#!/usr/bin/env python3
"""Independent keyless checks of bounded synthetic native/reference container bytes.

Not a PKG builder, signature validator, or installability test. No keys needed.
"""
import argparse
import hashlib
import importlib.util
import pathlib
import struct
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("authoring", HERE / "check-authoring.py")
AUTHORING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHORING)


def check(path, inner_size):
    checks = AUTHORING.integrity(path)
    data = path.read_bytes()  # Existing verifier caps synthetic input at 16 MiB.
    count, table = struct.unpack_from(">I", data, 0x10)[0], struct.unpack_from(">I", data, 0x18)[0]
    records = {}
    for index in range(count):
        entry_id, _, _, _, offset, length = struct.unpack_from(">6I", data, table + index * 32)
        records[entry_id] = data[offset:offset + length]
    dat = bytearray(416)
    struct.pack_into("<4s6HIHHIHH", dat, 0, b"plgo", 0, 0, 1, 1, 1, 1, 416, 0, 1, 0, 0, 0)
    if records[0x1001][4:8] == b"\x00\x30\x00\x00":
        dat[4:8] = records[0x1001][4:8]
        dat[24:28] = records[0x1001][24:28]
    dat[32:64] = bytes([255]) * 32
    dat[64:100] = data[0x40:0x64]
    # Section (offset, declared length) directory, including inner microchunk last.
    sections = [(256, 32), (288, 2), (304, 9), (320, 16),
                (352, 32), (384, 2), (400, 12), (336, 16)]
    for index, pair in enumerate(sections):
        struct.pack_into("<II", dat, 192 + 8 * index, *pair)
    struct.pack_into("<BBB11xHQII", dat, 256, 128, 0, 3, 1, 2**64 - 1, 0, 0)
    dat[304:313] = b"Chunk #0\0"
    struct.pack_into("<QQQQ", dat, 320, 0, len(data), 0, inner_size)
    struct.pack_into("<B19xHHII", dat, 352, 1, 1, 1, 0, 0)
    dat[400:412] = b"Scenario #0\0"
    assert records[0x1001] == dat, "PlayGo DAT"
    manifest = ET.fromstring(records[0x1003])
    assert manifest.tag == "psproject" and manifest.attrib == {"fmt": "playgo-manifest", "version": "0990"}
    volume, = manifest
    info, = volume
    scenarios, = info
    scenario, = scenarios
    assert volume.tag == "volume" and not volume.attrib
    assert info.tag == "chunk_info" and info.attrib == {"chunk_count": "1", "scenario_count": "1"}
    assert scenarios.tag == "scenarios" and scenarios.attrib == {"default_id": "0"}
    assert scenario.tag == "scenario" and scenario.attrib == {
        "id": "0", "type": "sp", "initial_chunk_count": "1", "label": "Scenario #0"}
    assert scenario.text == "0" and not list(scenario)
    sfo = records[0x1000]
    magic, version, keys, values, count = struct.unpack_from("<4sIIII", sfo)
    assert magic == b"\0PSF" and version == 0x101
    fields = {}
    for index in range(count):
        key_offset, fmt, length, capacity, offset = struct.unpack_from("<HHIII", sfo, 20 + 16 * index)
        assert length <= capacity
        key = sfo[keys + key_offset:].split(b"\0", 1)[0]
        raw = sfo[values + offset:values + offset + length]
        fields[key] = (fmt, raw)
    major = bytearray()
    for key in [b"ATTRIBUTE", b"ATTRIBUTE2", b"CATEGORY", b"FORMAT", b"PUBTOOLVER"]:
        if key == b"ATTRIBUTE2" and key not in fields:
            continue
        fmt, raw = fields[key]
        if key in [b"CATEGORY", b"FORMAT"]:
            assert fmt == 0x204
            value = raw.split(b"\0", 1)[0]
            value.decode("ascii")
        else:
            assert fmt == 0x404 and len(raw) == 4
            value = f"0x{struct.unpack('<I', raw)[0]:08x}".encode("ascii")
        major.extend(key + value)
    sha = lambda value: hashlib.sha256(value).digest()
    major_hash = sha(major)
    general = bytearray(384)
    struct.pack_into(">HH24xI", general, 0, 0xd256, 0x100, 0x6e)
    general[32:64] = sha(data[0x40:0x78] + data[0x440:0x460] + major_hash)
    general[64:96] = data[0x440:0x460]
    general[96:128] = sha(data[:0x40] + data[0x400:0x480])
    general[160:192] = major_hash
    general[192:224] = sha(sfo)
    assert records[0x80] == general, "general digests"
    print(f"Passed {len(checks)} layout/hash checks plus exact DAT, manifest semantics and all supported general digest slots")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("synthetic", type=pathlib.Path)
    parser.add_argument("--inner-size", required=True, type=lambda value: int(value, 0))
    args = parser.parse_args()
    check(args.synthetic, args.inner_size)
