#!/usr/bin/env python3
"""Disposable synthetic GP4 -> native images -> pinned external reader checks."""
import argparse
import hashlib
import importlib.util
import pathlib
import secrets
import struct
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
PIN = "643477263b2644e0803e0f58b8726ea4e3f3b7d4"


def sfo():
    fields = sorted({"CATEGORY": "gd", "CONTENT_ID": "ZZ0000-CUSA00000_00-SYNTHETIC0000000",
                     "TITLE_ID": "CUSA00000", "APP_VER": "01.00", "VERSION": "01.00"}.items())
    keys, values, entries = bytearray(), bytearray(), bytearray()
    for key, value in fields:
        while len(values) % 4:
            values.append(0)
        raw = value.encode() + b"\0"
        entries += struct.pack("<HHIII", len(keys), 0x204, len(raw), len(raw), len(values))
        keys += key.encode() + b"\0"
        values += raw
    key_start = 20 + len(entries)
    value_start = (key_start + len(keys) + 3) // 4 * 4
    result = struct.pack("<4sIIII", b"\0PSF", 0x101, key_start, value_start, len(fields)) + entries + keys
    return result + bytes(value_start - len(result)) + values


def run(dotnet, reference, output, cli):
    reference, output, cli = reference.resolve(), output.resolve(), cli.resolve()
    assert subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip() == PIN
    assert not subprocess.check_output(["git", "-C", str(reference), "status", "--porcelain"]), "dirty reference"
    assert subprocess.check_output([dotnet, "--version"], text=True).strip() == "8.0.425"
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("extraction_build", HERE / "build-extraction.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    builder.build(dotnet, reference, output / "reader")
    subprocess.run([dotnet, "build", str(HERE / "InnerImage.csproj"),
                    f"-p:ReferenceRoot={reference}", f"-p:ReferencePfsc={output / 'reader/PFSCReader.net8.cs'}",
                    f"-p:BaseIntermediateOutputPath={output / 'oracle-obj'}/",
                    "-o", str(output / "oracle")], check=True)
    source = output / "source"
    source.mkdir()
    for path in ["data", "B_", "empty-dir", "sce_sys"]:
        (source / path).mkdir()
    files = {"eboot.bin": b"synthetic, not executable", "data/boundary.bin": bytes(range(251)) * 4000,
             "empty-file": b"", "A~": b"", "sce_sys/param.sfo": sfo(),
             "sce_sys/keystone": bytes([7]) * 96}
    for name in ["icon0.png", "pic0.png", "pic1.png", "snd0.at9"]:
        files["sce_sys/" + name] = ("opaque synthetic resource: " + name).encode()
    for name, data in files.items():
        (source / name).write_bytes(data)
    before = {name: hashlib.sha256(data).digest() for name, data in files.items()}
    passcode = output / "passcode"
    passcode.write_text(secrets.token_hex(16))
    passcode.chmod(0o600)
    project = output / "source.gp4"
    subprocess.run([cli, "gp4", "create", source, project, "--passcode-file", passcode,
                    "--timestamp", "2026-10-31 12:34:56"], check=True)
    for extension in ["pfs", "pfsc"]:
        image = output / ("inner." + extension)
        subprocess.run([cli, "gp4", "image", project, image, "--source-root", source], check=True, cwd=source)
        subprocess.run([dotnet, output / "oracle/InnerImage.dll", image, source], check=True)
        assert image.stat().st_size < 16 * 1024 * 1024
        # UTC date conversion is checked separately from the native reader.
        with image.open("rb") as stream:
            header = stream.read(65536)
            start = struct.unpack_from("<Q", header, 32)[0] if extension == "pfsc" else 0
            stream.seek(start + 0x68)
            assert struct.unpack("<q", stream.read(8))[0] == 1793450096
        digest = hashlib.sha256(image.read_bytes()).digest()
        repeated = subprocess.run([cli, "gp4", "image", project, image, "--source-root", source], capture_output=True)
        assert repeated.returncode != 0 and hashlib.sha256(image.read_bytes()).digest() == digest
    assert all(hashlib.sha256((source / name).read_bytes()).digest() == value for name, value in before.items())
    print("PASS: GP4 pipeline, independent clear/wrapped reads, UTC timestamp, no overwrite, unchanged synthetic sources; no PKG/crypto/hardware claim")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dotnet")
    parser.add_argument("reference", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("cli", type=pathlib.Path)
    args = parser.parse_args()
    run(args.dotnet, args.reference, args.output, args.cli)
