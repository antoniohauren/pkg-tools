#!/usr/bin/env python3
"""Prepare an original zero-passcode sentinel source; accept a native rebuilt PKG.

Synthetic only, not a runnable homebrew/console acceptance test. Stdlib only.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CONTENT_ID = b"ZZ0000-CUSA00000_00-SYNTHETIC0000000"
PLAYGO = {"sce_sys/playgo-chunk.dat", "sce_sys/playgo-chunk.sha", "sce_sys/playgo-manifest.xml"}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUTHORING = load("check-authoring")
CONTAINER = load("check-container")


def synthetic(path):
    if not 0x100000 <= path.stat().st_size <= AUTHORING.MAX_SIZE:
        raise ValueError("expected bounded original synthetic package")
    with path.open("rb") as source:
        header = source.read(0x70)
    if header[:4] != b"\x7fCNT" or header[0x40:0x64] != CONTENT_ID:
        raise ValueError("only original synthetic fixture accepted")


def readback(dotnet, prepared, package, output):
    with output.open("x") as destination:
        subprocess.run([dotnet, str(prepared / "reader/Extraction.dll"), str(package)], stdout=destination, check=True)
    result = json.loads(output.read_text())
    if (result["outerMode"], result["innerMode"], result["pfscBlockSize"]) != (13, 8, 65536):
        raise ValueError("unexpected rebuilt image profile")
    return result


def preserved(source, native):
    """Full payload/resource comparison, excluding only regenerated PlayGo bytes."""
    if set(source["files"]) != set(native["files"]) or source["directories"] != native["directories"]:
        raise ValueError("rebuilt namespace differs")
    for name, expected in source["files"].items():
        if name not in PLAYGO and native["files"][name] != expected:
            raise ValueError("rebuilt payload/resource differs: " + name)


def signature_corruption(dotnet, prepared, package, output):
    """Fake header is outside keyless digest coverage; require pinned rejection too."""
    corrupted = output / "signature-corrupt.pkg"
    with package.open("rb") as source, corrupted.open("xb") as destination:
        shutil.copyfileobj(source, destination, AUTHORING.BLOCK)
    try:
        with corrupted.open("r+b") as destination:
            destination.seek(0x1000)
            byte = destination.read(1)
            destination.seek(0x1000)
            destination.write(bytes([byte[0] ^ 1]))
        AUTHORING.integrity(corrupted)
        report = output / "signature-corruption.json"
        result = subprocess.run([dotnet, str(prepared / "builder/Authoring.dll"), "--validate-synthetic",
                                 str(corrupted), str(report)], capture_output=True, text=True)
        validations = json.loads(report.read_text())["results"]
        rejected = [v["name"] for v in validations if v["result"] != "Ok"]
        if result.returncode == 0 or rejected != ["PKG Header Signature"]:
            raise ValueError("pinned validator did not isolate fake-header corruption")
        return "PKG Header Signature (pinned validator; keyless checks still pass)"
    finally:
        corrupted.unlink()


def prepare(args):
    reference, output, cli = args.reference.resolve(), args.output.resolve(), args.cli.resolve()
    if subprocess.check_output([args.dotnet, "--version"], text=True).strip() != AUTHORING.SDK:
        raise ValueError("wrong .NET SDK")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    load("build-extraction").build(args.dotnet, reference, output / "reader")
    subprocess.run([args.dotnet, "build", str(HERE / "Authoring.csproj"),
                    f"-p:ReferenceRoot={reference}", f"-p:ReferencePfsc={output / 'reader/PFSCReader.net8.cs'}",
                    f"-p:BaseIntermediateOutputPath={output / 'builder-obj'}/", "-o", str(output / "builder")], check=True)
    subprocess.run([args.dotnet, str(output / "builder/Authoring.dll"), "--synthetic-zero-passcode", str(output / "fixture")], check=True)
    package = output / "fixture/synthetic.pkg"
    synthetic(package)
    CONTAINER.check(package, 0x550000)
    manifest = readback(args.dotnet, output, package, output / "source-readback.json")
    expected = json.loads((output / "fixture/expected.json").read_text())
    if (set(manifest["files"]) != set(expected["files"]) | set(expected["generated"])
            or manifest["directories"] != expected["directories"]):
        raise ValueError("unexpected source namespace")
    for name, value in expected["files"].items():
        if name != "sce_sys/param.sfo" and manifest["files"][name] != value:
            raise ValueError("source payload differs: " + name)
    subprocess.run([str(cli), "extract", str(package), str(output / "source-tree")], check=True)
    subprocess.run([sys.executable, str(HERE / "compare-extraction.py"), str(output / "source-readback.json"), str(output / "source-tree")], check=True)
    (output / "setup.json").write_text(json.dumps({"reference": AUTHORING.PIN, "sdk": AUTHORING.SDK,
        "synthetic_only": True, "runnable": False, "source_inner_size": 0x550000}) + "\n")
    print("Prepared original synthetic source and extracted tree; eboot sentinel CANNOT launch")


def verify(args):
    prepared, package, output, cli = args.prepared.resolve(), args.package.resolve(), args.output.resolve(), args.cli.resolve()
    setup = json.loads((prepared / "setup.json").read_text())
    if setup != {"reference": AUTHORING.PIN, "sdk": AUTHORING.SDK, "synthetic_only": True,
                 "runnable": False, "source_inner_size": 0x550000}:
        raise ValueError("wrong synthetic setup")
    if subprocess.check_output([args.dotnet, "--version"], text=True).strip() != AUTHORING.SDK:
        raise ValueError("wrong .NET SDK")
    synthetic(package)
    if package == (prepared / "fixture/synthetic.pkg").resolve() or os.path.samefile(package, prepared / "fixture/synthetic.pkg"):
        raise ValueError("acceptance requires separate native output, not source package")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    CONTAINER.check(package, args.inner_size)
    subprocess.run([args.dotnet, str(prepared / "builder/Authoring.dll"), "--validate-synthetic", str(package), str(output / "validation.json")], check=True)
    native = readback(args.dotnet, prepared, package, output / "native-readback.json")
    # Re-read source too: neither cached manifests nor native extraction define expected payloads.
    source = readback(args.dotnet, prepared, prepared / "fixture/synthetic.pkg", output / "source-readback.json")
    preserved(source, native)
    subprocess.run([str(cli), "extract", str(package), str(output / "native-tree")], check=True)
    subprocess.run([sys.executable, str(HERE / "compare-extraction.py"), str(output / "native-readback.json"), str(output / "native-tree")], check=True)
    corruptions = AUTHORING.corruption_checks(package, output / "corrupt.pkg")
    corruptions.append(signature_corruption(args.dotnet, prepared, package, output))
    (output / "evidence.json").write_text(json.dumps({
        "reference": AUTHORING.PIN, "sdk": AUTHORING.SDK, "native_output_supplied_by_caller": True,
        "files": len(native["files"]), "directories": len(native["directories"]),
        "preserved_payloads_and_resources": "every byte by independent reader size/SHA256, except regenerated PlayGo",
        "playgo": "exact default DAT, XML semantics and every package-relative stored-block SHA slot",
        "corruption_detected": corruptions,
        "adapter_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in
                           ["check-native-rebuild.py", "Authoring.cs", "Extraction.cs", "check-container.py", "check-authoring.py"]},
        "limits": ["caller must establish native writer provenance; copied reference output is not proof",
                   "sentinel eboot cannot launch", "reader authenticates PFS header, not all block HMACs",
                   "no >4 GiB, console install/launch, save, NP or trophy check", "reference tools share lineage"]}, indent=2) + "\n")
    print("Native-output synthetic structural acceptance passed; NOT PS4-ready or launch evidence")


def self_test():
    manifest = {"directories": ["data"], "files": {"eboot.bin": {"size": 1, "sha256": "original"},
                "sce_sys/keystone": {"size": 96, "sha256": "binding"},
                "sce_sys/playgo-chunk.sha": {"size": 4, "sha256": "old"}}}
    native = json.loads(json.dumps(manifest))
    native["files"]["sce_sys/playgo-chunk.sha"]["sha256"] = "regenerated"
    preserved(manifest, native)
    for name in ("eboot.bin", "sce_sys/keystone"):
        changed = json.loads(json.dumps(native))
        changed["files"][name]["sha256"] = "corrupt"
        try:
            preserved(manifest, changed)
        except ValueError:
            pass
        else:
            raise AssertionError("changed retained bytes accepted")
    changed = json.loads(json.dumps(native))
    del changed["files"]["eboot.bin"]
    try:
        preserved(manifest, changed)
    except ValueError:
        pass
    else:
        raise AssertionError("missing payload accepted")
    AUTHORING.self_test()
    print("Native rebuild comparison self-tests passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("self-test")
    setup = commands.add_parser("prepare")
    setup.add_argument("dotnet")
    setup.add_argument("reference", type=pathlib.Path)
    setup.add_argument("output", type=pathlib.Path)
    setup.add_argument("cli", type=pathlib.Path)
    accept = commands.add_parser("verify")
    accept.add_argument("dotnet")
    accept.add_argument("prepared", type=pathlib.Path)
    accept.add_argument("package", type=pathlib.Path)
    accept.add_argument("output", type=pathlib.Path)
    accept.add_argument("cli", type=pathlib.Path)
    accept.add_argument("--inner-size", required=True, type=lambda value: int(value, 0))
    args = parser.parse_args()
    {"self-test": lambda _: self_test(), "prepare": prepare, "verify": verify}[args.command](args)
