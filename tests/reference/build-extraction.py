#!/usr/bin/env python3
"""Build pinned reference with one .NET 8 short-read compatibility fix."""
import pathlib
import subprocess
import sys

PIN = "643477263b2644e0803e0f58b8726ea4e3f3b7d4"


def build(dotnet, reference, output):
    reference, output = reference.resolve(), output.resolve()
    revision = subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip()
    assert revision == PIN, "wrong reference revision"
    assert not subprocess.check_output(["git", "-C", str(reference), "status", "--porcelain"]), "reference checkout must be clean"
    source = (reference / "LibOrbisPkg/PFS/PFSCReader.cs").read_text()
    old = "ds.Read(output, 0, hdr.BlockSz);"
    assert source.count(old) == 1, "reference source changed"
    output.mkdir(parents=True, exist_ok=True)
    adapted = output / "PFSCReader.net8.cs"
    adapted.write_text(source.replace(old, "ds.ReadExactly(output, 0, hdr.BlockSz);"))
    subprocess.run([dotnet, "build", str(pathlib.Path(__file__).with_name("Extraction.csproj")),
                    f"-p:ReferenceRoot={reference}", f"-p:ReferencePfsc={adapted}", "-o", str(output)], check=True)
    subprocess.run([dotnet, str(output / "Extraction.dll"), "--self-test"], check=True)


if __name__ == "__main__":
    build(sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
