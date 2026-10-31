#!/usr/bin/env python3
"""Synthetic-only newcrypt/NP/resource source producer and native-output oracle.

Requires cryptography/OpenSSL. Uses existing reader constants locally, never logs
keys. Sentinel inputs only; NP/trophy bytes intentionally have no real identity.
"""
import argparse
import hashlib
import hmac
import pathlib
import re
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import importlib.util

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("native", HERE / "check-native-rebuild.py")
NATIVE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(NATIVE)
WRAP = NATIVE.load("check-container-crypto")
BLOCK = 65536
sha = lambda b: hashlib.sha256(b).digest()
mac = lambda k, b: hmac.digest(k, b, "sha256")


def derived(index):
    return sha(sha(struct.pack(">I", index)) + sha(NATIVE.CONTENT_ID + bytes(12)) + b"0" * 32)


def modulus(fake):
    text = (HERE.parent.parent / "crates/ps4-pkg/src/crypto.rs").read_text()
    prefix = "FAKE" if fake else "DK3"
    p, q = [int(re.search(rf'const {prefix}_{part}: &str = "([0-9a-f]+)"', text)[1], 16)
            for part in ("P", "Q")]
    return (p * q).to_bytes(256, "big")


def crypt(data, material, encrypt):
    assert len(data) % 16 == 0
    cipher = Cipher(algorithms.AES(material[16:]), modes.CBC(material[:16]))
    operation = cipher.encryptor() if encrypt else cipher.decryptor()
    return operation.update(data) + operation.finalize()


def parse(data):
    count, table = [struct.unpack_from(">I", data, p)[0] for p in (0x10, 0x18)]
    return {r[0]: r for r in [struct.unpack_from(">8I", data, table + i * 32) for i in range(count)]}


def contents(data, records):
    result = {}
    for id, record in records.items():
        stored = (record[5] + 15) // 16 * 16 if id == 0x403 else record[5]
        value = bytes(data[record[4]:record[4] + stored])
        if record[2] & 0x80000000:
            value = crypt(value, sha(struct.pack(">8I", *record) + derived(record[3] >> 12 & 7)), False)
        if id == 0x403:
            assert not any(value[record[5]:])
            value = value[:record[5]]
        result[id] = value
    return result


def pfs(data, key, replacement=None):
    """Authenticate every referenced block; optionally rekey/reseed bottom-up."""
    data = bytearray(data)
    u32 = lambda p: struct.unpack_from("<I", data, p)[0]
    u64 = lambda p: struct.unpack_from("<Q", data, p)[0]
    assert u64(0x30) == 4 and u64(0x40) == 1 and u64(0x38) * BLOCK == len(data)
    seed = bytes(data[0x370:0x380])
    signing = mac(key, struct.pack("<I", 2) + seed)
    assert mac(signing, data[:0x380] + bytes(0x220)) == data[0x380:0x3a0]

    def xts(key, seed, encrypt):
        material = mac(key, struct.pack("<I", 1) + seed)
        assert not any(data[4 * BLOCK:5 * BLOCK])
        for sector in range(16, len(data) // 4096):
            if sector // 16 == 4:
                continue
            cipher = Cipher(algorithms.AES(material[16:] + material[:16]), modes.XTS(sector.to_bytes(16, "little")))
            operation = cipher.encryptor() if encrypt else cipher.decryptor()
            p = sector * 4096
            data[p:p + 4096] = operation.update(data[p:p + 4096]) + operation.finalize()

    xts(key, seed, False)
    refs, used = [], {0, 4}

    def ref(p, wide=False):
        block = u64(p + 32) if wide else u32(p + 32)
        assert 0 < block < len(data) // BLOCK and block not in used
        used.add(block)
        assert mac(signing, data[block * BLOCK:(block + 1) * BLOCK]) == data[p:p + 32]
        refs.append((p, block))
        return block

    assert ref(0xb8, True) == 1
    for i in range(4):
        inode = BLOCK + i * 0x2c8
        count = u32(inode + 96)
        for j in range(min(count, 12)):
            ref(inode + 100 + j * 36)
        remaining = count - min(count, 12)
        if remaining:
            single = ref(inode + 100 + 12 * 36)
            for j in range(min(remaining, BLOCK // 36)):
                ref(single * BLOCK + j * 36)
            remaining -= min(remaining, BLOCK // 36)
        assert remaining == 0, "bounded synthetic oracle: single indirection only"
    assert used == set(range(len(data) // BLOCK))
    if replacement:
        new_key, seed = replacement
        signing = mac(new_key, struct.pack("<I", 2) + seed)
        for p, block in reversed(refs):
            data[p:p + 32] = mac(signing, data[block * BLOCK:(block + 1) * BLOCK])
        data[0x370:0x380] = seed
        data[0x380:0x3a0] = mac(signing, data[:0x380] + bytes(0x220))
        xts(new_key, seed, True)
    return bytes(data)


RESOURCES = {0x402: ("", 0xa0), 0x403: ("", 0x214),
             0x1004: ("pronunciation.xml", 37), 0x1005: ("pronunciation.sig", 33),
             0x1006: ("pic1.png", 31), 0x100d: ("save_data.png", 29),
             0x1200: ("icon0.png", 27), 0x1220: ("pic0.png", 25),
             0x1260: ("changeinfo/changeinfo.xml", 23), 0x1280: ("icon0.dds", 21),
             0x12a0: ("pic0.dds", 19), 0x12c0: ("pic1.dds", 17),
             0x1400: ("trophy/trophy00.trp", 65)}


def prepare(source, output):
    NATIVE.synthetic(source)
    old = source.read_bytes()
    records = parse(old)
    plain = contents(old, records)
    po, ps = struct.unpack_from(">QQ", old, 0x410)
    seed = bytes(range(16))
    ready = mac(derived(1), seed)
    outer = pfs(old[po:po + ps], derived(1), (ready, seed))
    pfs(outer, ready)
    plain[0x20] = WRAP.wrapping(modulus(True), ready)[1]
    for id, (_, length) in RESOURCES.items():
        plain[id] = bytes((id + i) % 251 for i in range(length))
    names = {id: bytes(plain[0x200][r[1]:]).split(b"\0", 1)[0].decode() for id, r in records.items()}
    names.update({id: value[0] for id, value in RESOURCES.items()})
    # Pinned builder's physical order: six system records, fixed application
    # records, then remaining resources in numeric ID order (NP slots follow licenses).
    order = [0x10, 0x20, 0x80, 0x100, 1, 0x200, 0x1001, 0x1002, 0x1003,
             0x400, 0x401, 0x402, 0x403, 0x1000, 0x409]
    order += sorted(set(plain) - set(order))
    name_data, offsets = bytearray(b"\0"), {}
    for id in sorted(order, key=lambda id: (names[id], id)):
        if names[id]:
            offsets[id] = len(name_data)
            name_data += names[id].encode() + b"\0"
    plain[0x200] = bytes(name_data)
    plain[0x100] = plain[1] = bytes(len(order) * 32)
    align = lambda n, a: (n + a - 1) // a * a
    for _ in range(10):
        offset, records = 0x2000, {}
        for id in order:
            flags, index = ((0x80000000, 3) if id in (0x402, 0x403) else (0, 0))
            if id in parse(old):
                flags, index = parse(old)[id][2:4]
                index >>= 12
            records[id] = (id, offsets.get(id, 0), flags, index << 12, offset, len(plain[id]), 0, 0)
            offset = align(offset + len(plain[id]), 16)
        po = align(offset, 0x80000)
        size = po + len(outer)
        if len(plain[0x1002]) == size // BLOCK * 4:
            break
        plain[0x1002] = bytes(size // BLOCK * 4)
    else:
        raise AssertionError("SHA layout did not converge")
    data = bytearray(size)
    data[:0x1000] = old[:0x1000]
    data[po:] = outer
    for p, value in [(4, 0x40000001), (0x10, len(order)), (0x18, records[0x100][4]),
                     (0x1c, sum(records[id][5] for id in (0x10, 0x20, 0x80, 0x100, 1))),
                     (0x7c, po), (0x80, 0x20190801), (0x84, 0x0ea8a9bd), (0x43c, 0x120000)]:
        struct.pack_into(">I", data, p, value)
    struct.pack_into(">H", data, 0x16, len(order))
    for p, value in [(0x28, po - 0x2000), (0x408, 0xa0000000000003cc), (0x410, po), (0x428, size), (0x430, size)]:
        struct.pack_into(">Q", data, p, value)
    dat = bytearray(plain[0x1001])
    struct.pack_into("<H", dat, 4, 0x3000)
    struct.pack_into("<I", dat, 24, 0x12345678)  # Public synthetic SDK sentinel.
    struct.pack_into("<Q", dat, 0x148, size)
    plain[0x1001] = bytes(dat)
    plain[0x100] = b"".join(struct.pack(">8I", *records[id]) for id in sorted(records))
    plain[0x1002] = bytes(po // BLOCK * 4) + b"".join(sha(outer[p:p + BLOCK])[:4] for p in range(0, len(outer), BLOCK))
    data[0x440:0x460], data[0x460:0x480] = sha(outer), sha(outer[:BLOCK])
    general = bytearray(plain[0x80])
    general[32:64] = sha(data[0x40:0x78] + data[0x440:0x460] + general[160:192])
    general[64:96] = data[0x440:0x460]
    general[96:128] = sha(data[:0x40] + data[0x400:0x480]); plain[0x80] = bytes(general)
    for id, record in records.items():
        value = plain[id]
        if id == 0x403:
            value += bytes((-len(value)) % 16)
        if record[2] & 0x80000000:
            value = crypt(value, sha(struct.pack(">8I", *record) + derived(record[3] >> 12)), True)
        data[record[4]:record[4] + len(value)] = value
    def entry(id):
        r = records[id]
        stored = (r[5] + 15) // 16 * 16 if id == 0x403 else r[5]
        return data[r[4]:r[4] + stored]
    digest = bytes(32) + b"".join(sha(entry(id)) for id in sorted(records) if id != 1)
    r = records[1]; data[r[4]:r[4] + r[5]] = digest
    data[0x100:0x120] = sha(b"".join(entry(id) for id in (0x10, 0x20, 0x80, 0x100, 1)))
    data[0x120:0x140] = sha(b"".join(entry(id) for id in (0x10, 0x20, 0x80)) + entry(0x100)[:192])
    data[0x140:0x160], data[0x160:0x180] = sha(digest), sha(data[0x2000:po])
    data[0xfe0:0x1000] = sha(data[:0xfe0])
    data[0x1000:0x1100] = WRAP.wrapping(modulus(False), sha(data[:0x1000]))[1]
    with output.open("xb") as f:
        f.write(data)
    NATIVE.CONTAINER.check(output, 0x550000)
    print("Prepared independently assembled nonzero-seed newcrypt source with padded NP/trophy/resources")


def verify(source, output):
    for path in (source, output):
        NATIVE.synthetic(path)
        NATIVE.CONTAINER.check(path, 0x550000)
    a, b = source.read_bytes(), output.read_bytes()
    assert struct.unpack_from(">I", b, 4)[0] == 1
    assert struct.unpack_from(">Q", b, 0x408)[0] == 0x80000000000003cc
    original, rebuilt = contents(a, parse(a)), contents(b, parse(b))
    assert rebuilt[0x20] == WRAP.wrapping(modulus(True), derived(1))[1]
    for start, end in [(4, 8), (24, 28)]:
        assert original[0x1001][start:end] == rebuilt[0x1001][start:end]
    for id in (0x10, 0x400, 0x401, 0x1000, *RESOURCES):
        assert original[id] == rebuilt[id], f"retained resource {id:x} changed"
    po, ps = struct.unpack_from(">QQ", b, 0x410)
    pfs(b[po:po + ps], derived(1))
    print("PASS: newcrypt-to-legacy conversion, exact licenses/NP/trophy/resources, every outer block HMAC")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    {"prepare": prepare, "verify": verify}[args.command](args.source, args.output)
