#!/usr/bin/env python3
"""Check native liberation with Python cryptography and independent format reads.

Usage: ps3-liberation.py SOURCE.pkg LICENSE.rap OUTPUT.pkg CLI
Checks every transformed payload in full; unchanged files <=128 KiB in full,
larger unchanged files' first/last 64 KiB. Does not test installation or launch.
Requires the test-only Python cryptography package.
"""
import hashlib
import hmac
import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


def hx(s):
    return bytes.fromhex(s)


FREE = hx('72f990788f9cff745725f08e4c128387')
OMAC2 = hx('6ba52976efda16ef3c339fb2971e256b')
OMAC3 = hx('9b515feacf75064981aa604d91a54e97')
KLIC = hx('f2fbca7a75b04edc1390638ccdfdd1ee')
ROOTS = {
    1: ('f9edd0301f770fabba8863d9897f0fea6551b09431f61312654e28f43533ea6b', 'a551ccb4a42c37a734a2b4f9657d5540'),
    10: ('03c21ad78fbb6a3d425e9aab1298f9fd70e29fd4e6e3a3c151205da50c413de4', '0a99d4d4f8301a88052d714ad2fb565e'),
    25: ('fbda75963fe690cff35b7aa7b408cf631744edef5f7931a04d58fd6a921ffdb3', 'f72c1d80ffda2e3bf085f4133e6d2805'),
    28: ('8103ea9db790578219c4cedf0592b43064a7d98b601b6c7bc45108c4047aa80f', '246f4b8328be6a2d394ede20479247c5'),
}


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def decrypt(key, data, mode=None):
    ctx = Cipher(algorithms.AES(key), mode or modes.ECB()).decryptor()
    return ctx.update(data) + ctx.finalize()


def cmac(key, data):
    ctx = CMAC(algorithms.AES(key))
    ctx.update(data)
    return ctx.finalize()


def integer(b, offset, size=4):
    return int.from_bytes(b[offset:offset+size], 'big')


def rap_key(rap):
    assert len(rap) == 16
    key = bytearray(decrypt(hx('869f7745c13fd890ccf29188e3cc3edf'), rap))
    order = [12, 3, 6, 4, 1, 11, 15, 8, 2, 7, 0, 5, 10, 14, 13, 9]
    e1 = hx('a93e1fd67c55a329b75fdda62a95c7a5')
    e2 = hx('67d45da3296d006a4e7c537bf5538c74')
    for _ in range(5):
        for i in order:
            key[i] ^= e1[i]
        for i in range(15, 0, -1):
            key[order[i]] ^= key[order[i-1]]
        borrow = 0
        for i in order:
            value = (key[i] - borrow) & 255
            if borrow != 1 or value != 255:
                borrow = int(value < e2[i])
            key[i] = (value - e2[i]) & 255
    return bytes(key)


class Package:
    def __init__(self, path, cli):
        self.file = open(path, 'rb')
        self.h = self.file.read(192)
        doc = json.loads(subprocess.check_output([cli, 'inspect', str(path), '--json']))
        self.entries = {e['path']: e for e in doc['entries']}
        self.doc = doc

    def read(self, name, offset=0, size=None):
        e = self.entries[name]
        if size is None:
            size = e['size']-offset
        start = e['offset']+offset
        pad = start % 16
        self.file.seek(integer(self.h, 32, 8)+start-pad)
        data = self.file.read(size+pad)
        assert len(data) == size+pad
        if self.h[4:6] == b'\x80\x00':
            iv = integer(self.h, 112, 16)+(start-pad)//16
            data = decrypt(hx('2e7b71d7c9c9a14ea3221f188828b8f8'), data, modes.CTR(iv.to_bytes(16, 'big')))
        else:
            assert self.h[4:6] == b'\0\0'
            seed = self.h[96:104]*2+self.h[104:112]*2+bytes(24)
            data = b''.join(xor(data[i:i+16], hashlib.sha1(seed+struct.pack('>Q', (start-pad+i)//16)).digest()) for i in range(0, len(data), 16))
        return data[pad:]


def verify_debug_container(pkg):
    h = pkg.h
    assert h[4:6] == bytes(2)
    hs = hashlib.sha1(h[:128]).digest()[3:19]
    assert hs == h[128:144]
    pkg.file.seek(192)
    metadata = pkg.file.read(integer(h, 32, 8)-192-64)
    ms = hashlib.sha1(metadata).digest()[3:19]
    assert pkg.file.read(16) == ms

    def stream(key, counter):
        seed = key[:8]*2+key[8:]*2+bytes(24)
        return hashlib.sha1(seed+struct.pack('>Q', counter)).digest()[:16]

    pad = b''.join(stream(ms, i) for i in range(3))
    assert pkg.file.read(48) == pad
    assert h[144:192] == xor(pad, b''.join(stream(hs, i) for i in range(3)))
    assert h[112:128] == stream(h[96:112], 2**64-1)
    pkg.file.seek(0, 2)
    assert pkg.file.tell() == integer(h, 24, 8)


def verify_signature(header, mh):
    p = int('9be59bc21226f8a144313b235e89a9c89a69cabb', 16)
    n = int('9be59bc21226f8a144304638d96be3234965be65', 16)
    g = (int('46853050e0342e747cda37bc437d53a90290a8ab', 16), int('3996e93f7a0ee6232f18eabf34cf5805d94fdb6c', 16))
    q = (int('3995c390c9f7fbbab124a1c14e70f9741a5e6bdf', 16), int('17a605d88239652c8ea7d5fc9f24b30546c1e44b', 16))

    def add(a, b):
        if a is None or b is None:
            return a if b is None else b
        x, y = a
        u, v = b
        if x == u and (y+v) % p == 0:
            return None
        slope = ((3*x*x-3)*pow(2*y, -1, p) if a == b else (v-y)*pow(u-x, -1, p)) % p
        xx = (slope*slope-x-u) % p
        return xx, (slope*(x-xx)-y) % p

    def mul(k, a):
        result = None
        while k:
            if k & 1:
                result = add(result, a)
            a = add(a, a)
            k >>= 1
        return result

    sig = integer(header, mh, 8)
    r, s = integer(header, sig, 21), integer(header, sig+21, 21)
    assert 0 < r < n and 0 < s < n
    z = int.from_bytes(hashlib.sha1(header[:sig]).digest(), 'big')
    w = pow(s, -1, n)
    assert add(mul(z*w % n, g), mul(r*w % n, q))[0] % n == r


def opaque_self_sections(data, header, records, verify_table):
    """Recognize non-runtime ELF data without treating its bytes as key material."""
    def bounded(start, size, limit):
        assert 0 <= start <= limit and 0 <= size <= limit-start
        return start, start+size

    def overlaps(a, b):
        return a[0] < a[1] and b[0] < b[1] and a[0] < b[1] and b[0] < a[1]

    if not any(integer(s, 16) in (2, 3) for s in records):
        return set()
    elf = integer(header, 48, 8)
    plain_end = integer(header, 12)+32
    bounded(elf, 64, plain_end)
    e = header[elf:elf+64]
    if (elf < 104 or e[:7] != b'\x7fELF\x02\x02\x01'
            or integer(e, 16, 2) != 2 or integer(e, 18, 2) != 21
            or integer(e, 20) != 1 or integer(e, 52, 2) != 64):
        return set()
    phnum, shnum = integer(e, 56, 2), integer(e, 60, 2)
    if (integer(e, 54, 2) != 56 or integer(e, 58, 2) != 64
            or phnum in (0, 0xffff) or not shnum or integer(e, 62, 2) >= shnum):
        return set()
    elf_size = integer(header, 24, 8)
    elf_ph = bounded(integer(e, 32, 8), phnum*56, elf_size)
    elf_sh = bounded(integer(e, 40, 8), shnum*64, elf_size)
    if elf_ph[0] < 64 or elf_sh[0] < elf_ph[1]:
        return set()
    phoff, shoff = integer(header, 56, 8), integer(header, 64, 8)
    bounded(phoff, phnum*56, plain_end)
    bounded(shoff, shnum*64, len(data))
    if phoff < elf+64:
        return set()
    # The section table itself still follows the ordinary authenticated path.
    tables = [s for s in records if integer(s, 16) == 1
              and integer(s, 0, 8) == shoff and integer(s, 8, 8) == shnum*64
              and integer(s, 24) == 2 and integer(s, 32) == integer(s, 44) == 1]
    if len(tables) != 1:
        return set()
    programs = []
    for j in range(phnum):
        p = header[phoff+j*56:phoff+(j+1)*56]
        programs.append(bounded(integer(p, 8, 8), integer(p, 32, 8), elf_size))
    storage = [bounded(integer(s, 0, 8), integer(s, 8, 8), len(data)) for s in records]
    ordered = sorted(r for r in storage if r[0] < r[1])
    if any(r[0] < len(header) for r in storage) or any(
            a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        return set()
    indices = [integer(s, 20) for s in records if integer(s, 16) == 3]
    opaque = set()
    if any(overlaps(elf_sh, p) for p in programs):
        return opaque
    segments = integer(header, 72, 8)
    bounded(segments, phnum*32, plain_end)
    if segments < phoff+phnum*56:
        return opaque
    for j in range(phnum):
        s = header[segments+j*32:segments+(j+1)*32]
        r = bounded(integer(s, 0, 8), integer(s, 8, 8), len(data))
        if overlaps(r, (shoff, shoff+shnum*64)):
            return opaque
    table = tables[0]
    table_authenticated = verify_table(table, data[shoff:shoff+shnum*64])
    if any(integer(s, 16) == 2 for s in records):
        opaque.add(records.index(table))
    # Unauthenticated preserved tables never authorize another hash exemption.
    if not table_authenticated:
        return opaque
    for i, s in enumerate(records):
        if integer(s, 16) != 3 or integer(s, 32) != 1 or integer(s, 44) != 1:
            continue
        index = integer(s, 20)
        if not 0 < index < shnum or indices.count(index) != 1:
            continue
        sh = data[shoff+index*64:shoff+(index+1)*64]
        if (integer(sh, 4) != 1 or integer(sh, 8, 8) != 0 or integer(sh, 16, 8) != 0
                or not integer(sh, 32, 8) or integer(sh, 32, 8) != integer(s, 8, 8)):
            continue
        elf_range = bounded(integer(sh, 24, 8), integer(sh, 32, 8), elf_size)
        if any(overlaps(elf_range, p) for p in [(0, 64), elf_ph, elf_sh]+programs):
            continue
        if any(j != i and overlaps(storage[i], r) for j, r in enumerate(storage)):
            continue
        opaque.add(i)
    return opaque


def self_sections(data, key, free=False):
    b = bytearray(data[:integer(data, 16, 8)])
    mi = integer(b, 12)+32
    erk, iv = map(hx, ROOTS[integer(b, 8, 2)])
    info = decrypt(decrypt(KLIC, key), bytes(b[mi:mi+64]), modes.CBC(bytes(16)))
    info = decrypt(erk, info, modes.CBC(iv))
    assert info[16:32] == info[48:64] == bytes(16)
    b[mi:mi+64] = info
    mh = mi+64
    b[mh:] = decrypt(info[:16], bytes(b[mh:]), modes.CTR(info[32:48]))
    count = integer(b, mh+12)
    keys = mh+32+count*48
    key_end = keys+integer(b, mh+16)*16
    assert 0 < count <= 65536 and key_end <= len(b)
    records = [b[mh+32+i*48:mh+32+(i+1)*48] for i in range(count)]

    def verify_hash(record, payload):
        hi = keys+integer(record, 28)*16
        assert integer(record, 24) == 2 and hi+96 <= key_end
        return hmac.digest(bytes(b[hi+32:hi+96]), payload, 'sha1') == b[hi:hi+20]

    opaque_indices = opaque_self_sections(data, b, records, verify_hash)
    sections, opaque = [], []
    for i in range(count):
        s = mh+32+i*48
        offset, length = integer(b, s, 8), integer(b, s+8, 8)
        payload = data[offset:offset+length]
        assert len(payload) == length and offset >= len(b)
        hi = keys+integer(b, s+28)*16
        assert integer(b, s+24) == 2 and hi+96 <= key_end
        if i in opaque_indices:
            opaque.append((bytes(b[s:s+48]), bytes(b[hi:hi+96]), payload))
            continue
        if integer(b, s+32) == 3:
            k = keys+integer(b, s+36)*16
            iv = keys+integer(b, s+40)*16
            payload = decrypt(bytes(b[k:k+16]), payload, modes.CTR(bytes(b[iv:iv+16])))
        assert verify_hash(records[i], payload)
        sections.append(zlib.decompress(payload) if integer(b, s+44) == 2 else payload)
    if free:
        npd = b.index(b'NPD\0')
        assert integer(b, npd+8) == 3
        assert cmac(xor(FREE, OMAC2), bytes(b[npd:npd+96])) == b[npd+96:npd+112]
        verify_signature(b, mh)
    return sections, opaque


def edat_plain(b, key):
    version, flags = integer(b, 4), integer(b, 128)
    assert version in (2, 3, 4) and flags in ((0x0c,) if version == 2 else (0x0c, 0x3c))
    wrap = hx('4ca9c14b01c95309969bec68aa0bc081' if version == 4 else 'be959ca8308defa2e5e180c63712a9ae')
    assert cmac(decrypt(wrap, key), b[:160]) == b[160:176]
    size, block = integer(b, 136, 8), integer(b, 132)
    count = (size+block-1)//block
    metadata, plain = b'', b''
    for i in range(count):
        if flags == 0x3c:
            mo = 256+i*(block+32)
            md = b[mo:mo+32]
            offset = mo+32
        else:
            assert flags == 0x0c
            md = b[256+i*16:272+i*16]
            offset = 256+count*16+i*block
        metadata += md
        length = min(block, size-i*block)
        data = b[offset:offset+(length+15)//16*16]
        seed = b[96:108]+struct.pack('>I', i)
        ctx = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        bk = ctx.update(seed)
        hk = decrypt(wrap, ctx.update(bk) if flags == 0x3c else bk)
        if flags == 0x3c:
            assert hmac.digest(hk+bytes(4), data, 'sha1') == xor(md[:16], md[16:])+md[16:20]
        else:
            assert cmac(hk, data) == md
        plain += decrypt(decrypt(wrap, bk), data, modes.CBC(b[64:80]))[:length]
    assert cmac(decrypt(wrap, key), metadata) == b[144:160]
    return plain


def main(source, rap, output, cli):
    src, dst = Package(source, cli), Package(output, cli)
    verify_debug_container(dst)
    key = rap_key(Path(rap).read_bytes())
    assert src.entries.keys() == dst.entries.keys()
    assert src.h[48:96] == dst.h[48:96]
    assert dst.h[4:6] == bytes(2)
    assert dst.doc['metadata'][0]['raw_hex'] == '00000003'
    sections, changed = [], []
    candidates = [FREE, key, bytes(16)]
    for name, entry in src.entries.items():
        if entry['kind'] == 'directory':
            continue
        magic = src.read(name, 0, min(4, entry['size']))
        if magic == b'SCE\0':
            print('Checking SELF:', name, flush=True)
            a, b = src.read(name), dst.read(name)
            original = self_sections(a, key)
            converted = self_sections(b, FREE, True)
            assert original == converted
            sections.extend(original[0])
            assert integer(a, 16, 8) == integer(b, 16, 8)
            assert a[integer(a, 16, 8):] == b[integer(b, 16, 8):]
            changed.append(name)
    for name, entry in src.entries.items():
        if entry['kind'] == 'directory' or name in changed:
            continue
        magic = src.read(name, 0, min(4, entry['size']))
        if magic == b'NPD\0' and integer(src.read(name, 0, 16), 8) == 2:
            print('Checking EDAT:', name, flush=True)
            a, b = src.read(name), dst.read(name)
            assert integer(b, 8) == 3
            def matches(k):
                return cmac(xor(k, OMAC2), b[:96]) == b[96:112]
            devkey = next((k for k in candidates if matches(k)), None)
            if devkey is None:
                devkey = next(s[i:i+16] for s in sections for i in range(len(s)-15) if matches(s[i:i+16]))
                candidates.append(devkey)
            assert edat_plain(a, key) == edat_plain(b, devkey)
            changed.append(name)
        else:
            size = entry['size']
            assert size == dst.entries[name]['size']
            for offset in {0, max(0, size-65536)}:
                length = min(65536, size-offset)
                assert src.read(name, offset, length) == dst.read(name, offset, length), name
    print('Verified decoded SELF hashes/signature, opaque auxiliary preservation, EDAT hashes/plaintext, and unchanged-file samples:')
    for name in changed:
        print(' ', name)


if __name__ == '__main__':
    main(*sys.argv[1:])
