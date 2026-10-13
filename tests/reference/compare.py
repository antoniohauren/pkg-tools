"""Compare trusted local packages; write title-specific results only to private output.

Usage: python3 compare.py DOTNET ORACLE_DLL PKG_TOOLS OUTPUT_DIR INPUT.pkg ...
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

dotnet, oracle, cli, destination, *inputs = sys.argv[1:]
assert inputs, "at least one package required"
destination = Path(destination)
destination.mkdir(parents=True, exist_ok=True)
for index, source in enumerate(inputs):
    expected = json.loads(subprocess.check_output([dotnet, oracle, source]))
    actual = json.loads(subprocess.check_output([cli, "inspect", source, "--json"]))
    for key, value in expected["header"].items():
        assert actual["header"][key] == value, (key, "header differs")
    assert actual["entries"] == expected["entries"], "container table differs"
    assert actual["sfo"]["status"] == "available"
    assert len(actual["sfo"]["entries"]) == len(expected["sfo"])
    for want, got in zip(expected["sfo"], actual["sfo"]["entries"]):
        for key, value in want.items():
            assert got[key] == value, (want["key"], key, "SFO differs")
    entry = next(e for e in expected["entries"] if e["id"] == 0x1000)
    with open(source, "rb") as stream:
        stream.seek(entry["offset"])
        sfo = stream.read(entry["size"])
    assert len(sfo) == entry["size"]
    result = {
        "reference_revision": "643477263b2644e0803e0f58b8726ea4e3f3b7d4",
        "input": str(Path(source).resolve()),
        "sfo_sha256": hashlib.sha256(sfo).hexdigest(),
        "expected": expected,
        "actual": actual,
    }
    (destination / f"inspection-{index}.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"fixture {index}: header, {len(expected['entries'])} container entries, "
          f"{len(expected['sfo'])} SFO values match")
