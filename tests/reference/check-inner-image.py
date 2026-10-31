#!/usr/bin/env python3
"""Independent keyless checks for inner-image-synthetic outputs; no PKG claims."""
import pathlib
import struct
import sys

BLOCK = 65536


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def unwrap(data):
    if data[:4] != b"PFSC":
        return data
    assert struct.unpack_from("<IIIQQQQ", data, 4) == (
        0, 6, BLOCK, BLOCK, 0x400, u64(data, 32), u64(data, 40)
    )
    size, start = u64(data, 40), u64(data, 32)
    count = size // BLOCK
    assert size % BLOCK == 0 and len(data) == start + size
    assert start == ((0x400 + (count + 1) * 8 + BLOCK - 1) // BLOCK) * BLOCK
    assert not any(data[48:0x400])
    assert not any(data[0x400 + (count + 1) * 8:start])
    for index in range(count + 1):
        assert u64(data, 0x400 + index * 8) == start + index * BLOCK
    return data[start:]


def verify(data):
    data = unwrap(data)
    assert u64(data, 0) == 1 and u64(data, 8) == 20130315
    assert data[24:32] == b"\0\0\1\0\10\0\0\0"
    assert u32(data, 32) == BLOCK and u64(data, 40) == 1
    count, blocks, table_blocks = (u64(data, offset) for offset in (48, 56, 64))
    assert len(data) == blocks * BLOCK and table_blocks == (count + 389) // 390
    assert u64(data, 0xd8) == 1 and u32(data, 0xb0) == table_blocks
    assert u64(data, 0x58) == table_blocks * BLOCK
    assert u64(data, 0x60) == table_blocks * BLOCK
    assert all(u64(data, offset) == 123 for offset in (0x68, 0x70, 0x78, 0x80))
    inodes, used = [], set(range(1 + table_blocks))
    for number in range(count):
        offset = (1 + number // 390) * BLOCK + (number % 390) * 168
        inode = data[offset:offset + 168]
        mode, links, flags, size, stored = struct.unpack_from("<HHIQQ", inode)
        assert mode in (0x416d, 0x816d) and size == stored and links > 0
        assert flags == (0x20010 if number < 3 else 0x10)
        assert all(u64(inode, p) == 123 for p in (24, 32, 40, 48))
        start, allocated = u32(inode, 100), u32(inode, 96)
        assert allocated == (size + BLOCK - 1) // BLOCK
        assert all(u32(inode, p) == 0xffffffff for p in range(104, 148, 4))
        assert not any(inode[148:])
        extent = set(range(start, start + allocated))
        assert not (used & extent) and start + allocated <= blocks
        used.update(extent)
        payload = data[start * BLOCK:start * BLOCK + size]
        assert not any(data[start * BLOCK + size:(start + allocated) * BLOCK])
        inodes.append((mode, payload, links))
    for block in range(1, table_blocks + 1):
        occupied = min(390, count - (block - 1) * 390) * 168
        assert not any(data[block * BLOCK + occupied:(block + 1) * BLOCK])
    assert all(not any(data[b * BLOCK:(b + 1) * BLOCK]) for b in range(blocks) if b not in used)

    def dirents(payload):
        result = []
        for block in range(0, len(payload), BLOCK):
            pos, end = block, min(block + BLOCK, len(payload))
            while pos < end:
                number, kind, length, size = struct.unpack_from("<IIII", payload, pos)
                if size == 0:
                    assert not any(payload[pos:end])
                    break
                assert size % 8 == 0 and size >= length + 17 and pos + size <= end
                name = payload[pos + 16:pos + 16 + length].decode("ascii")
                assert not any(payload[pos + 16 + length:pos + size])
                result.append((name, number, kind))
                pos += size
        return result

    superroot = {name: number for name, number, _ in dirents(inodes[0][1])}
    assert superroot == {"flat_path_table": 1, "collision_resolver": 2, "uroot": 3}
    paths = {}

    def walk(number, parent, prefix):
        children = dirents(inodes[number][1])
        assert children[:2] == [(".", number, 4), ("..", parent, 5)]
        assert inodes[number][2] == (3 if number == 3 else 2) + sum(kind == 3 for _, _, kind in children[2:])
        for name, child, kind in children[2:]:
            assert kind in (2, 3) and 0 <= child < len(inodes)
            path = prefix + name
            assert path not in paths
            paths[path] = (child, kind)
            assert inodes[child][0] == (0x416d if kind == 3 else 0x816d)
            if kind == 3:
                walk(child, number, path + "/")

    walk(3, 3, "")
    expected = {"A~", "B_", "data", "data/boundary.bin", "empty-dir"}
    expected.update(f"file{i:05}" for i in range(9000))
    assert set(paths) == expected
    assert sum(kind == 3 for _, kind in paths.values()) == 3
    for path, (number, kind) in paths.items():
        if kind == 2:
            payload = inodes[number][1]
            if path == "data/boundary.bin":
                assert payload == bytes(i % 251 for i in range(13 * BLOCK + 1))
            else:
                assert payload == b""
    groups = {}
    for path, value in paths.items():
        value_hash = 0
        for byte in ("/" + path).upper().encode("ascii"):
            value_hash = (value_hash * 31 + byte) & 0xffffffff
        groups.setdefault(value_hash, []).append((path, value))
    lookup = inodes[1][1]
    assert len(lookup) == len(groups) * 8
    resolver, resolver_offset = inodes[2][1], 0
    for index, (key, group) in enumerate(sorted(groups.items())):
        assert u32(lookup, index * 8) == key
        value = u32(lookup, index * 8 + 4)
        if len(group) == 1:
            _, (number, kind) = group[0]
            assert value == number | (0x20000000 if kind == 3 else 0)
        else:
            assert value == 0x80000000 | resolver_offset
            for path, (number, kind) in sorted(group):
                ino, entry_kind, length, size = struct.unpack_from("<IIII", resolver, resolver_offset)
                assert (ino, entry_kind) == (number, kind)
                assert resolver[resolver_offset + 16:resolver_offset + 16 + length] == ("/" + path).encode("ascii")
                assert size == ((length + 24) // 8) * 8
                assert not any(resolver[resolver_offset + 16 + length:resolver_offset + size])
                resolver_offset += size
            assert not any(resolver[resolver_offset:resolver_offset + 24])
            resolver_offset += 24
    assert resolver_offset == len(resolver)
    return data


def main():
    for filename in sys.argv[1:]:
        # This harness accepts only bounded generated synthetic images, never game data.
        path = pathlib.Path(filename)
        assert path.stat().st_size <= 16 * 1024 * 1024
        data = verify(path.read_bytes())
        # Payload and lookup corruption must both be caught by independent checks.
        for number in (1, 8):
            inode = BLOCK + number * 168
            offset = u32(data, inode + 100) * BLOCK
            changed = bytearray(data)
            changed[offset] ^= 1
            try:
                verify(changed)
            except (AssertionError, UnicodeError, struct.error):
                pass
            else:
                raise AssertionError("corruption was not detected")
        print("PASS: independent layout, allocation, payload, padding, lookup/collision and corruption checks:", path.name)


if __name__ == "__main__":
    main()
