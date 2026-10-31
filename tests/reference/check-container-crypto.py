#!/usr/bin/env python3
"""Independent synthetic metadata CBC + deterministic public RSA format oracle.

Uses Python's own MT19937, hashlib, integer pow and OpenSSL-backed AES.
No package constants, private keys, game inputs or whole-package claims.
"""
import argparse
import hashlib
import pathlib
import random
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Public half of an original disposable generated RSA-2048 pair; private half discarded.
MODULUS = bytes.fromhex(
    "8b458489ad2f98c341e0ddd4fb04ed58ecae5458d0fee4bceec3c9d1cc823d945"
    "6825d80320b93121dae015814792ee8fcf83a46576751d7ac3599b83b80d5781d"
    "5884323905714665d289d3fd4b711ca8a70efd5a85150e5d82c0f69eac48b0ddc"
    "561d0ac05ced75183f0e84eea47addc06cda3aa74a8efa7e8ef3192a2ea7611"
    "57a24f88acb9e9fbc197262eca1b1917420a8408975fe53bde67cc54626c4866d"
    "3529d99c9e72b3c46ac7d6906251163af3f4981a90a961795e4a6ea2c803de6e"
    "47adb7503726fbd9a036da8bfcad3589c892a748df4e6f1f7ac3ac84a4fec1cac"
    "b53ba12ff8b6b74eb14d0c2d799809ed83c01401597ead9ef0b06bbde915"
)
ID = b"ZZ0000-CUSA00000_00-SYNTHETIC0000000"
PASSCODE = bytes(range(0x21, 0x41))
sha = lambda value: hashlib.sha256(value).digest()


def wrapping(modulus, message):
    seed = struct.unpack(">8I", sha(sha(modulus + message)))
    # CPython seeds MT by little-endian u32 limbs of an integer (init_by_array).
    integer = sum(word << (32 * index) for index, word in enumerate(seed))
    assert seed[-1] != 0  # Preserve all eight seed limbs for this vector.
    mt = random.Random(integer)
    padding = bytearray()
    while len(padding) < 221:
        source = struct.pack(">12I", *(mt.getrandbits(32) for _ in range(12)))
        padding.extend(byte for byte in sha(source) if byte)
    block = b"\0\2" + padding[:221] + b"\0" + message
    ciphertext = pow(int.from_bytes(block, "big"), 65537,
                     int.from_bytes(modulus, "big")).to_bytes(256, "big")
    return block, ciphertext


def vectors():
    message = bytes(range(32))
    block, wrapped = wrapping(MODULUS, message)
    result = MODULUS + message + block + wrapped
    for entry_id, index, offset, flags in [
        (0x401, 2, 0x3000, 0x80000000),
        (0x400, 3, 0x3000, 0x80000000),
        (0x400, 3, 0x3010, 0x80000000),
        (0x400, 3, 0x3000, 0xc0000000),
    ]:
        record = struct.pack(">8I", entry_id, 0, flags, index << 12, offset, 32, 0, 0)
        derived = sha(sha(struct.pack(">I", index)) + sha(ID + bytes(12)) + PASSCODE)
        material = sha(record + derived)
        plain = bytes(range(17)) + bytes(15)
        encryptor = Cipher(algorithms.AES(material[16:]), modes.CBC(material[:16])).encryptor()
        encrypted = encryptor.update(plain) + encryptor.finalize()
        result += record + plain + encrypted
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native", type=pathlib.Path)
    args = parser.parse_args()
    expected = vectors()
    assert args.native.stat().st_size == len(expected)
    assert args.native.read_bytes() == expected, "native deterministic RSA/padding/metadata mismatch"
    print("Passed exact independent RSA padding/public exponentiation and four metadata CBC vectors")
