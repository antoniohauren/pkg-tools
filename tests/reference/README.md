# Independent inspection oracle

This optional test adapter compiles unmodified inspection-related sources from
LibOrbisPkg revision `643477263b2644e0803e0f58b8726ea4e3f3b7d4` in an external
checkout. Nothing upstream is vendored or linked into the Rust tools. The
reference remains LGPLv3; its test binary is a local artifact, not a release
dependency. .NET 8 SDK and Python 3 are needed only for this comparison.

From the workspace root (adjust paths):

```sh
git -C /tmp/opencode/pkg-references/LibOrbisPkg rev-parse HEAD
# Must equal 643477263b2644e0803e0f58b8726ea4e3f3b7d4; checkout must be clean.
git -C /tmp/opencode/pkg-references/LibOrbisPkg status --short
dotnet build tests/reference/Oracle.csproj \
  -p:ReferenceRoot=/tmp/opencode/pkg-references/LibOrbisPkg \
  -o /tmp/opencode/pkg-oracle
cargo build -p pkg-cli
python3 tests/reference/compare.py "$(command -v dotnet)" \
  /tmp/opencode/pkg-oracle/Oracle.dll target/debug/pkg-tools \
  pkgs/reference-inspection /path/to/base.pkg /path/to/patch.pkg
```

The adapter calls upstream `PkgReader.ReadHeader`, `MetaEntry.Read` and
`ParamSfo.FromStream`. Builder/PFS sources are excluded: their .NET Framework 4
tuple extensions conflict with .NET 8. Parser sources are not modified. Upstream
obsolete-crypto warnings are expected; the adapter does not invoke crypto.

Use trusted local fixtures: upstream readers are not hardened corruption-test
targets. This comparison requires plaintext SFO and types understood by the
reference. Unknown SFO formats are covered by Rust synthetic tests instead.

The Python script asserts equality for every exposed header field shared with
the oracle, every container record, and SFO keys, format tags, capacities, values
and reserialized used bytes. It records raw SFO SHA-256 and both JSON outputs in
the private destination. This is not full PKG hashing or extraction; original
input fingerprints remain in `pkgs/inventory.json`. Keep title-specific results
under ignored `pkgs/` or outside the repository.

## Executed result, 2026-10-13

Linux, .NET SDK 8.0.425, Rust 1.99.0:

- Local base candidate: header, 26 container entries and 25 SFO values matched.
- Local patch candidate: header, 18 container entries and 25 SFO values matched.
- Private results: `pkgs/reference-inspection/inspection-{0,1}.json`.

Some encrypted container records have non-block-aligned declared data lengths.
Inspection preserves those lengths; do not infer malformed CBC data solely from
the declared logical size. Milestone 3 resolved the CBC/CFB-tail storage rule;
see [extraction contract](../../docs/extraction.md).

## Extraction oracle (milestone 3)

`Extraction.csproj` uses the same pinned source plus PFS/PFSC and XTS readers.
Build through the adapter script, then hash the decoded application tree:

```sh
python3 tests/reference/build-extraction.py /tmp/opencode/dotnet/dotnet \
  /tmp/opencode/pkg-references/LibOrbisPkg /tmp/opencode/pkg-extraction-oracle
mkdir -p pkgs/reference-extraction
/tmp/opencode/dotnet/dotnet /tmp/opencode/pkg-extraction-oracle/Extraction.dll \
  /path/to/base.pkg > pkgs/reference-extraction/oracle-0.json
cargo build --release -p pkg-cli
target/release/pkg-tools extract /path/to/base.pkg pkgs/extracted-base
python3 tests/reference/compare-extraction.py \
  pkgs/reference-extraction/oracle-0.json pkgs/extracted-base
```

Repeat for patch with distinct manifest/output names. The adapter hashes file
bytes through upstream `GetView()` and includes all directories plus recognized
container application resources. It retains raw SFO and runtime PlayGo bytes;
it does not run GP4's metadata edits or executable decryption. The comparison
asserts complete path sets, sizes and SHA-256, and writes a private
`*.comparison.json` summary beside each manifest. No title data belongs in the
committed source tree.

Three explicitly documented adapter choices:

1. A local tuple extension resolves the .NET Framework shim versus .NET 8
   `Deconstruct` ambiguity, without editing upstream files.
2. Recovered image keys are passed with PFS flags zero: the new-crypt transform
   has already happened before image-key wrapping. Applying LibOrbisPkg's
   passcode-oriented flag transform again fails on both real fixtures.
   [Evidence and corrected contract](../../docs/extraction.md).
3. **One source adaptation is necessary on .NET 8.** Upstream PFSC calls
   `DeflateStream.Read` once, ignoring its permitted short return. With .NET 8,
   this gives partially zero-filled blocks and incorrect file hashes. The build
   script checks the exact revision and clean checkout, writes an external
   scratch copy changing that one call to `ReadExactly`, and compiles it instead.
   All other upstream code stays unchanged; no upstream implementation is
   vendored into this repository. The generated scratch source remains LGPLv3.

`--self-test` includes a 64 KiB synthetic PFSC block reproducing the short read.
It fails with the unadapted source and passes with the one-line adaptation; the
build script runs it automatically. It also prints the upstream XTS sector-16
SHA-256 used by the Rust crypto known-answer test. CBC/HMAC and the unaligned
CBC/CFB tail have separate NIST/RFC/OpenSSL known-answer coverage in Rust.

Executed on Linux/.NET 8.0.425: **2,735 files / 632 directories** for base,
**1,848 files / 851 directories** for full update. Every extracted path, size
and SHA-256 matched. Both use encrypted signed S32 outer PFS, unsigned D32 inner
PFS and 64 KiB PFSC blocks. Original fingerprints and manifests stay in `pkgs/`.
No fixture with a real >4 GiB file was available; virtual Rust tests cover those
offsets/lengths. Other variants and emulator compatibility remain unverified.
# ZArchive writer interoperability

Requires C++17 compiler and system libzstd development files (test-only):

```sh
git clone https://github.com/Exzap/ZArchive.git /tmp/opencode/zarchive-reference
git -C /tmp/opencode/zarchive-reference checkout 965b66c8d67b6b7e30fd63b3b75aa91a99ff303b
python3 tests/reference/check-zarchive.py /tmp/opencode/zarchive-reference
python3 tests/reference/check-zarchive.py /tmp/opencode/zarchive-reference --large
```

The script checks the revision and tracked reader source cleanliness, builds the
Rust release CLI and original upstream reader, and generates disposable fixtures.
`--large` streams a sparse-generated >4 GiB file through both implementations.
No game data is required. See [results and reader limits](../../docs/zarchive.md).
