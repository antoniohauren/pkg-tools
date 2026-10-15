#!/usr/bin/env python3
"""Build pinned upstream reader and compare a generated directory archive."""
import hashlib
import pathlib
import random
import struct
import subprocess
import sys
import tempfile

reference = pathlib.Path(sys.argv[1]).resolve()
repo = pathlib.Path(__file__).resolve().parents[2]
pin = "965b66c8d67b6b7e30fd63b3b75aa91a99ff303b"
assert subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip() == pin
assert not subprocess.check_output(["git", "-C", str(reference), "diff", "HEAD", "--", "src", "include"])
subprocess.run(["cargo", "build", "--release", "-p", "pkg-cli"], cwd=repo, check=True)
with tempfile.TemporaryDirectory(prefix="zarchive-check-", dir="/tmp/opencode") as temporary:
    work = pathlib.Path(temporary)
    oracle = work / "reader"
    subprocess.run(["c++", "-std=c++17", "-O2", "-I" + str(reference / "include"),
                    str(repo / "tests/reference/zarchive-reader.cpp"),
                    str(reference / "src/zarchivereader.cpp"), "-lzstd", "-o", str(oracle)], check=True)
    tree = work / "tree"
    (tree / "Nested" / "empty-dir").mkdir(parents=True)
    rng = random.Random(42)
    for i, size in enumerate([0, 1, 65535, 65536, 65537, 19 * 65536 + 97]):
        (tree / "Nested" / f"noise-{i}").write_bytes(rng.randbytes(size))
        (tree / f"repeat-{i}").write_bytes(b"abc123" * (size // 6) + b"x" * (size % 6))
    for name in ["a", "AA", "Z", "é", "Ω", "n" * 127]:
        (tree / name).write_bytes(b"name test")
    if "--large" in sys.argv[2:]:
        with (tree / "Large").open("wb") as large:
            large.truncate(2**32 + 65537)
    archive = work / "test.zar"
    subprocess.run([str(repo / "target/release/pkg-tools"), "pack", str(tree), str(archive)], check=True)
    data = bytearray(archive.read_bytes())
    footer = len(data) - 144
    digest = data[footer + 96:footer + 128]
    data[footer + 96:footer + 128] = bytes(32)
    assert hashlib.sha256(data).digest() == digest
    sections = struct.unpack_from(">12Q", data, footer)
    index, length = sections[2:4]
    sizes = [n + 1 for record in range(index, index + length, 40)
             for n in struct.unpack_from(">16H", data, record + 8)]
    assert 65536 in sizes and any(1 < n < 65536 for n in sizes)
    subprocess.run([str(oracle), str(archive), str(tree)], check=True)
    print("Footer SHA-256, raw/compressed chunks and UTF-8 names verified")
    (tree / ("n" * 128)).write_bytes(b"unsupported name")
    rejected = work / "rejected.zar"
    result = subprocess.run([str(repo / "target/release/pkg-tools"), "pack", str(tree), str(rejected)])
    assert result.returncode != 0 and not rejected.exists()
