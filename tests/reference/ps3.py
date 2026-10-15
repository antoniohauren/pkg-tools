#!/usr/bin/env python3
"""Independent PS3 container-plaintext oracle; Python stdlib + OpenSSL CLI.

Layout/crypto baseline: RPCS3 6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4,
Crypto/unpkg.{h,cpp}, key_vault.h. This does not execute the RPCS3 installer.
Trusted fixtures only. Decrypted data is spooled to a temporary file, not RAM.
"""
import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path


def exact(source, size):
    data = source.read(size)
    assert len(data) == size, "short input"
    return data


def digest_region(source, offset, size):
    source.seek(offset)
    digest = hashlib.sha256()
    while size:
        data = exact(source, min(size, 1024 * 1024))
        digest.update(data)
        size -= len(data)
    return digest.hexdigest()


def compare(package, output, cli):
    doc = json.loads(subprocess.check_output([cli, "inspect", str(package), "--json"]))
    assert doc["format"] == "ps3-pkg"
    with package.open("rb") as source, tempfile.TemporaryFile() as decoded:
        h = exact(source, 192)
        assert h[:4] == b"\x7fPKG"
        values = struct.unpack_from(">HH4I3Q", h, 4)
        fields = ("release_type", "platform", "metadata_offset", "metadata_count",
                  "metadata_size", "entry_count", "package_size", "data_offset", "data_size")
        header = dict(zip(fields, values))
        for name, value in header.items():
            assert doc["header"][name] == value, name
        assert doc["header"]["content_id_hex"] == h[48:96].hex()
        assert doc["header"]["qa_digest_hex"] == h[96:112].hex()
        assert doc["header"]["nonce_hex"] == h[112:128].hex()
        assert header["platform"] == 1 and header["package_size"] == package.stat().st_size
        source.seek(header["metadata_offset"])
        metadata = []
        for _ in range(header["metadata_count"]):
            ident, size = struct.unpack(">II", exact(source, 8))
            metadata.append({"id": ident, "raw_hex": exact(source, size).hex()})
        assert doc["metadata"] == metadata
        source.seek(header["data_offset"])
        remaining = header["data_size"]
        if header["release_type"] == 0x8000:
            with subprocess.Popen(["openssl", "enc", "-aes-128-ctr", "-K",
                                   "2e7b71d7c9c9a14ea3221f188828b8f8", "-iv", h[112:128].hex()],
                                  stdin=subprocess.PIPE, stdout=decoded) as process:
                while remaining:
                    chunk = exact(source, min(remaining, 1024 * 1024))
                    process.stdin.write(chunk)
                    remaining -= len(chunk)
                process.stdin.close()
                assert process.wait() == 0, "OpenSSL decryption failed"
        else:
            assert header["release_type"] == 0
            seed = h[96:104] * 2 + h[104:112] * 2 + bytes(24)
            block = 0
            while remaining:
                chunk = exact(source, min(remaining, 16))
                stream = hashlib.sha1(seed + struct.pack(">Q", block)).digest()
                decoded.write(bytes(a ^ b for a, b in zip(chunk, stream)))
                remaining -= len(chunk)
                block += 1
        decoded.flush()
        records = []
        decoded.seek(0)
        for _ in range(header["entry_count"]):
            records.append(struct.unpack(">IIQQII", exact(decoded, 32)))
        files, directories = {}, set()
        cli_entries = {e["path"]: e for e in doc["entries"]}
        for name_offset, name_size, offset, size, flags, pad in records:
            decoded.seek(name_offset)
            name = exact(decoded, name_size).rstrip(b"\0").decode("ascii")
            path = Path(name)
            assert not path.is_absolute() and all(p not in (".", "..") for p in name.split("/"))
            assert pad == 0 and flags & ~0x800000ff == 0
            assert (flags & 255) in (1, 2, 3, 4, 9)
            entry = cli_entries[name]
            assert (entry["offset"], entry["size"], entry["flags"]) == (offset, size, flags)
            directories.update(str(p) for p in path.parents if str(p) != ".")
            if flags & 255 == 4:
                directories.add(name)
                assert entry["kind"] == "directory"
                continue
            assert entry["kind"] == "file"
            expected = digest_region(decoded, offset, size)
            target = output / path
            assert target.stat().st_size == size, name
            with target.open("rb") as file:
                assert digest_region(file, 0, size) == expected, name
            files[name] = {"size": size, "sha256": expected}
            if name == "PARAM.SFO":
                decoded.seek(offset)
                sfo = exact(decoded, size)
                assert sfo[:4] == b"\0PSF"
                version, keys, values, count = struct.unpack_from("<4I", sfo, 4)
                assert doc["sfo"]["version"] == version
                assert len(doc["sfo"]["entries"]) == count
                for i, value in enumerate(doc["sfo"]["entries"]):
                    key, fmt, length, capacity, pos = struct.unpack_from("<HHIII", sfo, 20 + 16 * i)
                    assert value["key_hex"] == sfo[keys+key:sfo.index(0, keys+key)].hex()
                    assert (value["format"], value["length"], value["max_length"]) == (fmt, length, capacity)
                    assert value["raw_hex"] == sfo[values+pos:values+pos+length].hex()
                    assert value["padding_hex"] == sfo[values+pos+length:values+pos+capacity].hex()
        actual_files, actual_dirs = set(), set()
        for path in output.rglob("*"):
            assert not path.is_symlink()
            (actual_dirs if path.is_dir() else actual_files).add(str(path.relative_to(output)))
        assert actual_files == set(files)
        assert actual_dirs == directories
        assert set(cli_entries) == set(files) | directories
        return {"files": files, "directories": sorted(directories), "header": header}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("extracted", type=Path)
    parser.add_argument("cli")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    result = compare(args.package, args.extracted, args.cli)
    if args.manifest:
        with args.manifest.open("x") as manifest:
            json.dump(result, manifest, indent=2)
    print(f"Matched {len(result['files'])} files, {len(result['directories'])} directories; header, metadata, SFO, sizes and SHA-256.")
