#!/usr/bin/env python3
"""Independent original synthetic outer-PFS oracle; requires cryptography/OpenSSL.

Uses no Rust reader/writer implementation. Inputs match outer-image-synthetic.
Format origins: pinned L PFSBuilder/PfsStructs/Crypto, documented in README.
No private keys, game data, fixtures or fingerprints are consumed or printed.
"""
import hashlib
import hmac
import pathlib
import struct
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 65536
REFS = BLOCK // 36
KEY = bytes(range(32))  # Public synthetic test input, never a package key.


def material(seed, index):
    return hmac.digest(KEY, struct.pack("<I", index) + seed, "sha256")


def kat():
    seed = bytes(range(16))
    enc = material(seed, 1)
    assert enc.hex() == "76be34e86d4a3793c4f2af46f63879f41b876753b3609b58c497052fc4f416b6"
    assert material(seed, 2).hex() == "e9d9d5c076c2b31e0a95557f14f36f20b99cfcc788f7c09e640ada5f49eeb7bd"
    encryptor = Cipher(algorithms.AES(enc[16:] + enc[:16]), modes.XTS((16).to_bytes(16, "little"))).encryptor()
    ciphertext = encryptor.update(bytes(i % 251 for i in range(4096))) + encryptor.finalize()
    assert ciphertext[:32].hex() == "ceed998c169a81d5e1ea5c383d78f1eb6999d121bddec95ecb297ec0865a6d70"
    assert hashlib.sha256(ciphertext).hexdigest() == "af5cd198566f2d9370dfaf633d7c52c32e84f9390fadc8f16e0947d55a63b092"
    # Separately researched full legacy derivation recipe; no fixed secret inputs.
    content_id = b"ZZ0000-CUSA00000_00-SYNTHETIC0000000"
    passcode = bytes(0x21 + i for i in range(32))
    keys = [hashlib.sha256(hashlib.sha256(i.to_bytes(4, "big")).digest() + hashlib.sha256(content_id + bytes(12)).digest() + passcode).digest() for i in range(7)]
    assert hashlib.sha256(b"".join(keys)).hexdigest() == "5d9db1f987ef961cb0f904b8a7637a4be7e1bd3836f002dcb475eb0d2fce8473"
    for seed, expected_material, expected_cipher, expected_hmac in [
        (bytes(16), "b02114543bfb205623678c02f21df7e9619816e0d22bdb6da979a20d68a38914", "828b51da8f9f02e413b94ae8040419b20f15de95229ca73d77a949b217f4e2c5", "188040fd26cada2fb26e36e22fcbfc8ee657f7e7ceb0da9b04263b51d417aae5"),
        (bytes(range(16)), "53c45751d99c9076986bf98b72e9e094cbac6e97faeee65bfc5ca85961ed97e1", "9cd2b41a557c5c3e1d50cb27453f8cb99ba7b083c0f8bb499608f41e7d56330a", "92b7aceb3bbfdc8f96852005816c4bbf6532fa042dc803d445342869dde6b78f"),
    ]:
        enc, signing = [hmac.digest(keys[1], i.to_bytes(4, "little") + seed, "sha256") for i in (1, 2)]
        assert hashlib.sha256(enc + signing).hexdigest() == expected_material
        plain = bytes(i % 251 for i in range(4096))
        encryptor = Cipher(algorithms.AES(enc[16:] + enc[:16]), modes.XTS((19).to_bytes(16, "little"))).encryptor()
        assert hashlib.sha256(encryptor.update(plain) + encryptor.finalize()).hexdigest() == expected_cipher
        assert hashlib.sha256(hmac.digest(signing, plain + bytes(BLOCK - len(plain)), "sha256")).hexdigest() == expected_hmac


def u32(data, p):
    return struct.unpack_from("<I", data, p)[0]


def u64(data, p):
    return struct.unpack_from("<Q", data, p)[0]


def verify(path):
    data = bytearray(path.read_bytes())
    assert len(data) % BLOCK == 0
    assert (u64(data, 0), u64(data, 8), u32(data, 28), u32(data, 32)) == (1, 20130315, 13, BLOCK)
    assert u64(data, 48) == 4 and u64(data, 56) * BLOCK == len(data) and u64(data, 64) == 1
    seed = bytes(data[0x370:0x380])
    assert seed == bytes(16)
    covered = data[:0x5a0]
    covered[0x380:] = bytes(0x220)
    signing = material(seed, 2)
    assert hmac.compare_digest(hmac.digest(signing, covered, "sha256"), data[0x380:0x3a0])
    enc = material(seed, 1)
    assert not any(data[4 * BLOCK:5 * BLOCK])
    for block in range(1, len(data) // BLOCK):
        if block == 4:
            continue
        for sector in range(block * 16, (block + 1) * 16):
            offset = sector * 4096
            decryptor = Cipher(algorithms.AES(enc[16:] + enc[:16]), modes.XTS(sector.to_bytes(16, "little"))).decryptor()
            data[offset:offset + 4096] = decryptor.update(data[offset:offset + 4096]) + decryptor.finalize()

    used = {0, 4}
    refs = []

    def signed_ref(p, wide=False):
        block = u64(data, p + 32) if wide else u32(data, p + 32)
        assert 0 < block < len(data) // BLOCK and block not in used
        used.add(block)
        assert hmac.compare_digest(hmac.digest(signing, data[block * BLOCK:(block + 1) * BLOCK], "sha256"), data[p:p + 32])
        refs.append((p, block))
        return block

    assert signed_ref(0xb8, True) == 1
    inodes = [BLOCK + i * 0x2c8 for i in range(4)]
    blocks = []
    for number, inode in enumerate(inodes):
        assert u32(data, inode + 4) == [0x2000c, 0x2000c, 0xc, 0xd][number]
        assert all(u64(data, inode + p) == 123 for p in (24, 32, 40, 48))
        count = u32(data, inode + 96)
        assert count == (u64(data, inode + 8) + BLOCK - 1) // BLOCK
        direct = [signed_ref(inode + 100 + i * 36) for i in range(min(count, 12))]
        remaining = count - len(direct)
        if remaining:
            single = signed_ref(inode + 100 + 12 * 36)
            direct += [signed_ref(single * BLOCK + i * 36) for i in range(min(remaining, REFS))]
            remaining = count - len(direct)
        if remaining:
            double = signed_ref(inode + 100 + 13 * 36)
            for i in range((remaining + REFS - 1) // REFS):
                leaf = signed_ref(double * BLOCK + i * 36)
                direct += [signed_ref(leaf * BLOCK + j * 36) for j in range(min(count - len(direct), REFS))]
        assert len(direct) == count
        blocks.append(direct)
    assert used == set(range(len(data) // BLOCK))
    assert blocks[0] == [2] and blocks[1] == [3]

    def directory(block):
        p, result = block * BLOCK, []
        while u32(data, p + 12):
            ino, kind, length, size = struct.unpack_from("<IIII", data, p)
            assert size >= length + 17 and size % 8 == 0
            result.append((bytes(data[p + 16:p + 16 + length]), ino, kind))
            p += size
        return result

    assert directory(2) == [(b"flat_path_table", 1, 2), (b"uroot", 2, 3)]
    assert directory(blocks[2][0]) == [(b".", 2, 4), (b"..", 2, 5), (b"pfs_image.dat", 3, 2)]
    lookup = 0
    for b in b"/PFS_IMAGE.DAT":
        lookup = (lookup * 31 + b) & 0xffffffff
    assert struct.unpack_from("<II", data, 3 * BLOCK) == (lookup, 3)
    pfsc = b"".join(data[b * BLOCK:(b + 1) * BLOCK] for b in blocks[3])
    assert pfsc[:4] == b"PFSC" and len(pfsc) == u64(data, inodes[3] + 8)
    assert u64(pfsc, 40) == u64(data, inodes[3] + 16)
    start = u64(pfsc, 32)
    assert start + u64(pfsc, 40) == len(pfsc)
    for i in range(u64(pfsc, 40) // BLOCK + 1):
        assert u64(pfsc, 0x400 + i * 8) == start + i * BLOCK
    inner = pfsc[start:]
    # One synthetic inner file; D32 file inode 3, contiguous blocks.
    inode = BLOCK + 3 * 168
    size, first = u64(inner, inode + 8), u32(inner, inode + 100)
    assert size in (13 * BLOCK + 1, 1835 * BLOCK + 1)
    for offset in range(0, size, BLOCK):
        n = min(BLOCK, size - offset)
        assert inner[first * BLOCK + offset:first * BLOCK + offset + n] == bytes((offset + i) % 251 for i in range(n))
    # Perturb data, indirect, inode and header independently: recomputation fails.
    for p, block in refs:
        data[block * BLOCK] ^= 1
        assert not hmac.compare_digest(hmac.digest(signing, data[block * BLOCK:(block + 1) * BLOCK], "sha256"), data[p:p + 32])
        data[block * BLOCK] ^= 1
    covered[0x30] ^= 1
    assert hmac.digest(signing, covered, "sha256") != data[0x380:0x3a0]
    print("PASS: independent OpenSSL XTS, all plaintext block HMACs, allocation, PFSC, inner bytes, corruption" + (", double indirection" if len(blocks[3]) > 12 + REFS else ", single indirection"))


if __name__ == "__main__":
    kat()
    for name in sys.argv[1:]:
        verify(pathlib.Path(name))
    print("PASS: independent PFS HMAC/XTS synthetic known answers")
