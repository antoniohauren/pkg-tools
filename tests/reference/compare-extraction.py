#!/usr/bin/env python3
"""Compare an actual Rust extraction with the independent oracle manifest."""
import hashlib
import json
import pathlib
import sys


def compare(manifest, root):
    expected = json.loads(manifest.read_text())
    files, directories = {}, []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise AssertionError(f"unexpected symlink: {path}")
        name = path.relative_to(root).as_posix()
        if path.is_dir():
            directories.append(name)
        elif path.is_file():
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            files[name] = {"size": path.stat().st_size, "sha256": digest}
        else:
            raise AssertionError(f"unexpected special file: {path}")
    assert files.keys() == expected["files"].keys(), "file paths differ"
    assert set(directories) == set(expected["directories"]), "directory paths differ"
    for name, actual in files.items():
        assert actual == expected["files"][name], f"size/hash differs: {name}"
    result = {"matched": True, "files": len(files), "directories": len(directories),
              "bytes": sum(v["size"] for v in files.values())}
    manifest.with_suffix(".comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    compare(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
