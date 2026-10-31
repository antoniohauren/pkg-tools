#!/usr/bin/env python3
"""Synthetic-only pinned base builder/readback and keyless integrity checks."""
import argparse
import hashlib
import importlib.util
import io
import json
import pathlib
import os
import secrets
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
PIN = "643477263b2644e0803e0f58b8726ea4e3f3b7d4"
SDK = "8.0.425"
MAX_SIZE = 16 * 1024 * 1024
BLOCK = 0x10000
SYSTEM_ORDER = (0x10, 0x20, 0x80, 0x100, 1, 0x200)
REQUIRED = (*SYSTEM_ORDER, 0x400, 0x401, 0x409, 0x1000, 0x1001, 0x1002, 0x1003)


def digest(stream, offset, size):
    stream.seek(offset)
    result = hashlib.sha256()
    while size:
        block = stream.read(min(size, 65536))
        if not block:
            raise ValueError("truncated digest range")
        result.update(block)
        size -= len(block)
    return result.digest()


def integrity(path):
    """Independent Python/stdlib hashes; no copied keys or crypto implementation."""
    size = path.stat().st_size
    if not 0x100000 <= size <= MAX_SIZE:
        raise ValueError("not a bounded synthetic package")
    checks = []
    with path.open("rb") as source:
        header = source.read(0x1000)
        if header[:4] != b"\x7fCNT":
            raise ValueError("wrong magic")
        u32 = lambda offset: struct.unpack_from(">I", header, offset)[0]
        u64 = lambda offset: struct.unpack_from(">Q", header, offset)[0]
        u16 = lambda offset: struct.unpack_from(">H", header, offset)[0]

        def check(name, actual, expected):
            if actual != expected:
                raise ValueError("integrity mismatch: " + name)
            checks.append(name)

        def region(offset, length):
            if offset < 0 or length < 0 or offset > size or length > size - offset:
                raise ValueError("out-of-range region")

        def require(name, condition):
            check(name, bool(condition), True)

        def hashed(name, offset, length, expected):
            region(offset, length)
            check(name, digest(source, offset, length), expected)

        check("package size", u64(0x430), size)
        check("GD base type", u32(0x74), 0x1A)
        check("base flags", u32(0x78), 0x0A000000)
        body, body_size = u64(0x20), u64(0x28)
        pfs, pfs_size = u64(0x410), u64(0x418)
        region(body, body_size)
        region(pfs, pfs_size)
        check("body start", body, 0x2000)
        check("body/PFS boundary", body + body_size, pfs)
        check("PFS alignment", pfs % 0x80000, 0)
        require("PFS block length", pfs_size >= BLOCK and pfs_size % BLOCK == 0)
        check("PFS end", pfs + pfs_size, size)
        check("promote size", u32(0x7C), pfs)
        check("mount image size", u64(0x428), size)
        count, table = u32(0x10), u32(0x18)
        if not 1 <= count <= 64:
            raise ValueError("unexpected synthetic entry count")
        check("mirrored entry count", u16(0x16), count)
        check("SC entry count", u16(0x14), 6)
        region(table, count * 32)
        source.seek(table)
        raw_records = [source.read(32) for _ in range(count)]
        require("record reserved bytes", all(r[24:] == bytes(8) for r in raw_records))
        records = [struct.unpack(">6I8x", r) for r in raw_records]
        ids = [r[0] for r in records]
        check("unique sorted entry IDs", ids, sorted(set(ids)))
        require("required base entries", set(REQUIRED) <= set(ids))
        entries = {r[0]: (r[4], r[5]) for r in records}
        for offset, length in entries.values():
            region(offset, length)
            require("entry in body", body <= offset and offset + length <= pfs)
            check("entry alignment", offset % 16, 0)
        allocated = sorted(records, key=lambda r: r[4])
        check("physical system order", [r[0] for r in allocated[:6]], list(SYSTEM_ORDER))
        check("first entry at body start", allocated[0][4], body)
        for previous, current in zip(allocated, allocated[1:]):
            require("nonoverlapping entries", previous[4] + previous[5] <= current[4])
        check("METAS table location/length", entries[0x100], (table, count * 32))
        for entry_id, length in [(0x10, 0x800), (0x20, 0x100), (0x80, 0x180),
                                 (0x400, 0x400), (0x401, 0x200), (0x409, 0x2000)]:
            check(f"entry {entry_id:x} length", entries[entry_id][1], length)
        flags = {1: (0x40000000, 0), 0x10: (0x60000000, 0),
                 0x20: (0xE0000000, 0x3000), 0x80: (0x60000000, 0),
                 0x100: (0x60000000, 0), 0x200: (0x40000000, 0),
                  0x400: (0x80000000, 0x3000), 0x401: (0x80000000, 0x2000),
                  0x402: (0x80000000, 0x3000), 0x403: (0x80000000, 0x3000)}
        for record in records:
            check(f"entry {record[0]:x} flags", record[2:4], flags.get(record[0], (0, 0)))
        check("SC1 length", u32(0x1C), sum(entries[i][1] for i in SYSTEM_ORDER[:5]))
        check("PlayGo digest length", entries[0x1002][1], size // BLOCK * 4)
        names_offset, names_size = entries[0x200]
        source.seek(names_offset)
        names = source.read(names_size)
        require("initial empty entry name", names[:1] == b"\0")
        for record in records:
            name_offset = record[1]
            require("entry name boundary", name_offset < len(names) and
                    (name_offset == 0 or names[name_offset - 1] == 0))
            end = names.find(b"\0", name_offset)
            require("terminated ASCII entry name", end >= 0 and
                    all(byte < 128 for byte in names[name_offset:end]))

        hashed("header", 0, 0xFE0, header[0xFE0:0x1000])
        hashed("body", body, body_size, header[0x160:0x180])
        hashed("PFS first block", pfs, BLOCK, header[0x460:0x480])
        hashed("PFS image", pfs, pfs_size, header[0x440:0x460])
        offset, length = entries[1]
        check("digest table length", length, count * 32)
        source.seek(offset)
        hashes = source.read(length)
        check("digest self slot", hashes[:32], bytes(32))
        hashed("digest table", offset, length, header[0x140:0x160])
        for index, record in enumerate(records[1:], 1):
            stored = (record[5] + 15) // 16 * 16 if record[0] == 0x403 else record[5]
            hashed(f"entry {record[0]:x}", record[4], stored, hashes[index * 32:(index + 1) * 32])
        for name, entry_ids, expected in [
            ("SC1", [0x10, 0x20, 0x80, 0x100, 1], header[0x100:0x120]),
            ("SC2", [0x10, 0x20, 0x80, 0x100], header[0x120:0x140]),
        ]:
            aggregate = hashlib.sha256()
            for entry_id in entry_ids:
                start, length = entries[entry_id]
                if name == "SC2" and entry_id == 0x100:
                    length = u16(0x14) * 32
                region(start, length)
                source.seek(start)
                aggregate.update(source.read(length))
            check(name, aggregate.digest(), expected)
        offset, length = entries[0x1002]
        source.seek(offset)
        playgo = source.read(length)
        check("PlayGo pre-PFS slots", playgo[:pfs // BLOCK * 4], bytes(pfs // BLOCK * 4))
        for block in range(pfs // BLOCK, size // BLOCK):
            check("PlayGo PFS block", playgo[block * 4:block * 4 + 4],
                  digest(source, block * BLOCK, BLOCK)[:4])
    return checks


def self_test():
    data = bytes(range(251)) * 1000
    assert digest(io.BytesIO(data), 7, 100000) == hashlib.sha256(data[7:100007]).digest()
    try:
        digest(io.BytesIO(b"short"), 0, 6)
    except ValueError:
        pass
    else:
        raise AssertionError("truncation accepted")
    print("Digest streaming/truncation self-test passed")
    subprocess.run([sys.executable, str(HERE / "test-authoring.py")], check=True)


def corruption_checks(package, corrupted):
    """Only called on this harness's generated synthetic fixture; preserve original."""
    with package.open("rb") as source:
        header = source.read(0x1000)
    pfs = struct.unpack_from(">Q", header, 0x410)[0]
    table = struct.unpack_from(">I", header, 0x18)[0]
    cases = [("header", 0x80), ("body", pfs - 1),
             ("PFS first block", pfs), ("PFS image", package.stat().st_size - 1),
             ("record reserved bytes", table + 24)]
    for expected, offset in cases:
        with package.open("rb") as src, corrupted.open("xb") as dst:
            shutil.copyfileobj(src, dst, BLOCK)
        try:
            with corrupted.open("r+b") as dst:
                dst.seek(offset)
                byte = dst.read(1)
                dst.seek(offset)
                dst.write(bytes([byte[0] ^ 1]))
            try:
                integrity(corrupted)
            except ValueError as error:
                assert str(error) == "integrity mismatch: " + expected, str(error)
            else:
                raise AssertionError("corruption not detected: " + expected)
        finally:
            corrupted.unlink()
    return [name for name, _ in cases]


def run(dotnet, reference, output, cli):
    reference, output, cli = reference.resolve(), output.resolve(), cli.resolve()
    assert subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip() == PIN
    assert not subprocess.check_output(["git", "-C", str(reference), "status", "--porcelain"]), "dirty reference"
    assert subprocess.check_output([dotnet, "--version"], text=True).strip() == SDK, "wrong SDK"
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("extraction_build", HERE / "build-extraction.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    builder.build(dotnet, reference, output / "reader")
    subprocess.run([dotnet, "build", str(HERE / "Authoring.csproj"),
                    f"-p:ReferenceRoot={reference}", f"-p:ReferencePfsc={output / 'reader/PFSCReader.net8.cs'}",
                    "-o", str(output / "builder")], check=True)
    subprocess.run([dotnet, str(output / "builder/Authoring.dll"), str(output / "fixture")], check=True)
    package = output / "fixture/synthetic.pkg"
    checks = integrity(package)
    # This bounded fixture uses L's minimum 0x55-block clear inner image.
    subprocess.run([sys.executable, str(HERE / "check-container.py"), str(package),
                    "--inner-size", "0x550000"], check=True)
    subprocess.run(["cargo", "test", "-p", "ps4-pkg", "--test", "container",
                    "pinned_reference_container_layout", "--", "--ignored"],
                   cwd=HERE.parent.parent,
                   env={**os.environ, "PKG_TOOLS_CONTAINER_REFERENCE": str(package)}, check=True)
    corruptions = corruption_checks(package, output / "corrupt.pkg")
    manifest = output / "readback.json"
    with manifest.open("x") as result:
        subprocess.run([dotnet, str(output / "reader/Extraction.dll"), str(package)], stdout=result, check=True)
    readback = json.loads(manifest.read_text())
    expected = json.loads((output / "fixture/expected.json").read_text())
    assert set(readback["files"]) == set(expected["files"]) | set(expected["generated"])
    assert readback["directories"] == expected["directories"]
    for name, value in expected["files"].items():
        if name != "sce_sys/param.sfo":
            assert readback["files"][name] == value, name
    assert (readback["outerMode"], readback["innerMode"], readback["pfscBlockSize"]) == (13, 8, 65536)
    subprocess.run([str(cli), "extract", str(package), str(output / "native")], check=True)
    subprocess.run(["python3", str(HERE / "compare-extraction.py"), str(manifest), str(output / "native")], check=True)
    # Keep GP4 secrets local, never command-line passcodes or evidence fields.
    gp4_source = output / "gp4-source"
    shutil.copytree(output / "native", gp4_source)
    (gp4_source / "empty & directory").mkdir()
    (gp4_source / "a&b's.bin").write_bytes(b"synthetic GP4 escaping test\n")
    passcode = output / "passcode"
    with open(passcode, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as secret:
        secret.write(secrets.token_hex(16))
    try:
        subprocess.run([str(cli), "gp4", "create", str(gp4_source), str(output / "generated.gp4"),
                        "--passcode-file", str(passcode), "--timestamp", "2026-01-01 00:00:00"], check=True)
    finally:
        passcode.unlink()
    subprocess.run([dotnet, str(output / "builder/Authoring.dll"), "--gp4",
                    str(output / "generated.gp4"), str(output / "reference.gp4")], check=True)
    # Only this harness's own bounded synthetic XML, never external inputs.
    variant = ET.parse(output / "generated.gp4")
    volume = variant.getroot().find("volume")
    identifier = ET.Element("volume_id")
    identifier.text = "Synthetic <&> Unicode λ"
    volume.insert(1, identifier)
    volume.find("package").set("c_date", "2024-02-29 03:04:05")
    volume.find("chunk_info/chunks/chunk").set("label", 'Chunk <&> "label"\nnext')
    volume.find("chunk_info/scenarios/scenario").set("label", "Scenario 'label'\t0")
    with open(output / "settings-generated.gp4", "xb", opener=lambda path, flags: os.open(path, flags, 0o600)) as destination:
        variant.write(destination, encoding="utf-8", xml_declaration=True)
    subprocess.run([dotnet, str(output / "builder/Authoring.dll"), "--gp4",
                    str(output / "settings-generated.gp4"), str(output / "settings-reference.gp4")], check=True)
    subprocess.run(["cargo", "test", "-p", "ps4-pkg", "--test", "gp4", "pinned_reference_roundtrip", "--", "--ignored"],
                   cwd=HERE.parent.parent, env={**os.environ, "PKG_TOOLS_GP4_REFERENCE_DIR": str(output)}, check=True)
    (output / "evidence.json").write_text(json.dumps({
        "reference": PIN, "sdk": SDK, "keyless_checks": checks, "corruption_detected": corruptions,
        "gp4": "native generation -> pinned reference load/tree/write -> native parse/preflight/settings/mappings equality",
        "adapter_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                            for name in ["Authoring.cs", "Authoring.csproj", "Extraction.cs", "build-extraction.py", "check-authoring.py", "test-authoring.py"]},
        "adapted_pfsc_sha256": hashlib.sha256((output / "reader/PFSCReader.net8.cs").read_bytes()).hexdigest(),
        "limits": ["SFO byte comparison excluded: reference changes PUBTOOL fields",
                   "builder and C# reader share lineage", "no all-block PFS HMAC validator", "not runnable"],
    }, indent=2) + "\n")
    print("Synthetic base build/readback and keyless integrity checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("paths", nargs="*", help="DOTNET REFERENCE NEW_OUTPUT PKG_TOOLS")
    args = parser.parse_args()
    self_test()
    if not args.self_test:
        if len(args.paths) != 4:
            parser.error("expected DOTNET REFERENCE NEW_OUTPUT PKG_TOOLS")
        run(args.paths[0], *(pathlib.Path(p) for p in args.paths[1:]))
