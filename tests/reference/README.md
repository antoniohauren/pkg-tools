# Independent inspection oracle

## Native signed/encrypted outer-PFS oracle

Uses original public synthetic image key/content-ID/passcode recipes, no game
data or additional fixed keys. `OuterImage.cs` compiles the same external pinned L
checkout and existing external .NET PFSC adaptation as the inner-image harness.
Python `check-outer-image.py` requires test-only `cryptography` (OpenSSL backend).
Production Rust has no new dependency or external process requirement.

```sh
cargo run -p ps4-pkg --example outer-image-synthetic -- /tmp/opencode/native-outer-single.pfs
cargo run -p ps4-pkg --example outer-image-synthetic -- /tmp/opencode/native-outer-double.pfs double
python3 tests/reference/check-outer-image.py /tmp/opencode/native-outer-single.pfs /tmp/opencode/native-outer-double.pfs
/path/to/dotnet build tests/reference/OuterImage.csproj \
  -p:ReferenceRoot=/path/to/clean/pinned-LibOrbisPkg \
  -p:ReferencePfsc=/path/to/existing/PFSCReader.net8.cs \
  -p:BaseIntermediateOutputPath=/tmp/opencode/outer-reference/obj/ \
  -o /tmp/opencode/outer-reference/bin/
/path/to/dotnet /tmp/opencode/outer-reference/bin/OuterImage.dll \
  /tmp/opencode/native-outer-single.pfs /tmp/opencode/native-outer-double.pfs
```

All checks executed successfully using L
`643477263b2644e0803e0f58b8726ea4e3f3b7d4`, .NET SDK 8.0.425,
Python 3.14.8 / cryptography 50.0.2 / OpenSSL 3.6.5. Upstream C# builds emit
obsolete-API/lowercase-type warnings; native Rust Clippy remains warning-free.
Re-run examples with fresh output filenames: existing files are intentionally refused.

Rust known answers assert RFC 4231 case 1 and NIST SP 800-38A F.2.2. Python and L
independently match original public synthetic PFS material, full legacy D[0..6]
derivation, zero/nonzero seed HMAC and XTS sector vectors documented in
[contract](../../docs/fpkg-authoring-contract.md#native-signedencrypted-outer-image-2026-10-31)
and [research findings](../../docs/crypto-unblocking-findings.md#reproducible-public-synthetic-known-answers).
Python decrypts every native sector, authenticates every referenced plaintext
padded block through direct/single/double references and header, verifies complete
nonaliasing allocation (except unreferenced clear zero block4), PFSC index/lookup/
namespace/patterned application bytes, and detects each block/header mutation.
L separately traverses outer/PFSC/inner and compares all application bytes.
Synthetic file sizes `13*65536+1` / `1835*65536+1` exercise single/double branches;
these are not >4-GiB or performance fixtures. Python may buffer whole synthetic
image; native writer uses bounded buffers and on-disk indexes.

No new crypto distribution approval, RSA/RIF/keystone encoder validation,
full-package output, NP/trophy, update/remarry, graphical, console/install/launch
or save-compatibility result. Existing reader authenticates header, not all blocks;
reader success alone is not the all-reference integrity check above.

## Native GP4 source-pipeline oracle

`check-gp4-image.py` generates a disposable synthetic source tree and GP4, runs
native `gp4 image` for clear/raw-PFSC output, and compares both with the pinned
independent LibOrbisPkg reader. Requires clean L revision
`643477263b2644e0803e0f58b8726ea4e3f3b7d4`, .NET SDK 8.0.425 and built CLI:

```sh
cargo build -p pkg-cli
python3 tests/reference/check-gp4-image.py /path/to/dotnet \
  /tmp/opencode/authoring-reference /tmp/opencode/gp4-image-new-run \
  target/debug/pkg-tools
```

Output root must not exist. Only generated synthetic inputs are accepted; no
package or application-directory argument. Root is private (0700); fresh passcode
file (0600) and GP4 stay there, never printed. Synthetic keystone is an opaque
96-byte sentinel, **not valid generated save/binding material**. Artwork/audio and
eboot are likewise non-runtime sentinels. Outputs/reference binaries stay local.
Uses existing external `ReadExactly` PFSC adaptation and tuple shims; no production
reference dependency/new source adaptation. Existing upstream builds emit 10
obsolete-API/lowercase-type warnings each, zero errors.

Executed 2026-10-31 on Linux: both images match complete independent inner file/
directory sets and all bytes: **5 inner files / 4 directories**, 1,004,480 total
source bytes, 1,004,000-byte boundary file, empty entries, `A~`/`B_` collision paths,
original keystone preserved. Five supported container resources are excluded;
this does not serialize/validate actual container records. Python independently
checks UTC inode timestamp, unchanged source hashes and refusal to replace outputs.
No hashes/passcodes are printed. `.pfs` is 5,570,560 bytes; `.pfsc` 5,636,096 bytes.
No PKG, crypto authentication, valid-keystone/artwork, console/save or large-file
claim. Native unit/integration tests separately exercise source changes, refusals,
cancellation and scratch cleanup.

## Native clear inner-image writer oracle

`inner-image-synthetic` generates original non-executable test data directly through
native `ps4_pkg::inner_image`; **not a PKG build or GP4 resource-placement test**.
Both clear D32 and raw PFSC outputs are checked by independent Python layout/lookup/
payload assertions and pinned LibOrbisPkg's separate reader. Use new output names:

```sh
cargo run -p ps4-pkg --example inner-image-synthetic -- /tmp/opencode/native-inner.pfs
cargo run -p ps4-pkg --example inner-image-synthetic -- /tmp/opencode/native-inner.pfsc
python3 tests/reference/check-inner-image.py /tmp/opencode/native-inner.pfs /tmp/opencode/native-inner.pfsc
```

After running the synthetic base harness below, reuse its external `.NET 8` PFSC
adapter (no new upstream source modification). Build output/obj stay outside repo:

```sh
/path/to/dotnet build tests/reference/InnerImage.csproj \
  -p:ReferenceRoot=/tmp/opencode/authoring-reference \
  -p:ReferencePfsc=/tmp/opencode/authoring-new-run/reader/PFSCReader.net8.cs \
  -p:BaseIntermediateOutputPath=/tmp/opencode/inner-reference/obj/ \
  -o /tmp/opencode/inner-reference/bin
/path/to/dotnet /tmp/opencode/inner-reference/bin/InnerImage.dll /tmp/opencode/native-inner.pfs
/path/to/dotnet /tmp/opencode/inner-reference/bin/InnerImage.dll /tmp/opencode/native-inner.pfsc
```

Executed 2026-10-31 on Linux/.NET SDK 8.0.425 against L
`643477263b2644e0803e0f58b8726ea4e3f3b7d4`: both images passed both oracles.
Each contains 9,002 files / 3 directories, a 851,969-byte patterned payload,
empty files/directories, `A~`/`B_` lookup collision, multi-block lookup/directory and
inode-block rollover. Python independently verifies full namespace/payload,
superblock/inode fields, extent allocation/non-overlap, zero padding, lookup order,
resolver contents and rejection of mutated lookup/payload bytes. Reference build
has 10 existing upstream obsolete-API/lowercase-type warnings, no errors. No new
production dependencies/crypto inputs. No crypto/authentication, full package,
actual >4-GiB payload, graphical, emulator or hardware result follows.

## Synthetic GD base authoring oracle

`check-authoring.py` builds a disposable base with external pinned LibOrbisPkg,
validates bytes read back from disk, compares its reader against native extraction,
and independently recomputes keyless integrity hashes in Python. It also checks
native standalone-app GP4 generation and pinned-reference round trips. No native
PKG writer/update implementation is added. Requires Python 3, **.NET SDK 8.0.425**
(not runtime alone), Rust CLI, and a clean reference checkout:

```sh
git clone https://github.com/maxton/LibOrbisPkg.git /tmp/opencode/authoring-reference
git -C /tmp/opencode/authoring-reference checkout 643477263b2644e0803e0f58b8726ea4e3f3b7d4
cargo build -p pkg-cli
python3 tests/reference/check-authoring.py --self-test
python3 tests/reference/check-authoring.py /path/to/dotnet \
  /tmp/opencode/authoring-reference /tmp/opencode/authoring-new-run \
  target/debug/pkg-tools
```

Output root must not exist. Use `/tmp/opencode` or ignored `pkgs/`; never publish
generated reference binaries, crypto records or packages. No package argument or
external application tree is accepted: all application bytes are original synthetic
data generated by `Authoring.cs`. `eboot.bin` is a **non-executable sentinel**, not
homebrew launch evidence. Other inputs: SFO, 65,537-byte patterned file, empty file
and empty directory. Runtime PlayGo and keystone are generated by reference.
Fresh passcode exists only in process memory; it is not logged or saved as config.
Checks are reproducible, **output bytes are not deterministic**.

The package adapter calls upstream `PkgBuilder.Write(Stream)` directly, not GP4 or CLI
patch build paths. Separate GP4 mode calls upstream `ReadFrom`, `BuildFSTree` and
`WriteTo` without building a package. Source files remain unchanged; C# tuple shims in PFS and PKG namespaces
resolve .NET 8 ambiguity. Existing `build-extraction.py` supplies its checked external
PFSC `ReadExactly` adaptation and runs reader self-tests. Expected upstream obsolete
crypto/lowercase-name warnings do not indicate Rust warnings.

Evidence is deliberately split:

* `fixture/validation.json`: every emitted upstream validation, location, type and
  result. **Fail and NoKey both fail run.** Also lists unverified categories;
  upstream silently skips unset/unknown general digests. These checks share builder
  lineage, so they are not a second independent format implementation.
* Python independently checks header/body/PFS first-block/full-image SHA256, digest
  table/self slot, every stored entry hash, both SC aggregate hashes, sorted unique
  IDs, GD base flags and physical size. Maximum accepted package is 16 MiB, with
  64 KiB hashing/copy buffers. Flipping final PFS byte in a new disposable copy must
  cause full-image digest failure. No corruption touches original fixture.
* `expected.json`: source path/size/hash expectations plus enumerated generated
  paths and SFO edits. C# checks unchanged SFO fields/types/capacities, allowing only
  PUBTOOLINFO/PUBTOOLVER changes. Python compares source payloads except edited SFO;
  native/reference extraction comparison covers **all output bytes including SFO**.
* `readback.json` and its comparison summary: all application paths, file sizes,
  SHA256 and empty directories match C# and native readers. `evidence.json` records
  reference/SDK pins, adapter/adapted-source hashes and explicit limits. No key dump.

Executed 2026-10-31 on Linux, SDK 8.0.425: **27/27 upstream validations Ok**,
including fake header match and debug RIF verification; Python integrity and
corruption detection pass; **8 files / 3 directories** agree with native extraction.
Outer mode `0x0d` (signed/encrypted plus upstream unknown-always-set `0x8`), inner
mode `0x08` (unsigned/clear), raw PFSC 64 KiB; generated keystone is 96 bytes.
This establishes an executed small synthetic **base structural oracle**, not
complete writer acceptance. All-block signed-PFS HMAC dependency checks, lookup
collision/rollover vectors, independent crypto known answers, >4 GiB, prepared
runnable homebrew, console install/launch/save/NP/trophy and every update-binding
gate remain open. No flatz reader run or hardware check is implied.

Required crypto inputs and unresolved distribution blockers:
[authoring provenance review](../../docs/fpkg-authoring-provenance.md).

### Base GP4 interchange evidence

The same command now copies only the generated synthetic extraction to a separate
`gp4-source` tree, adds escaped file/directory names, and runs native `gp4 create`
with a disposable private passcode file. It removes that file, then loads the GP4
in pinned L, constructs its filesystem tree (source resolution/file existence and
target hierarchy), and writes reference XML. A second synthetic variant exercises
optional volume ID, explicit creation date-time and escaped custom chunk/scenario
labels. Native opt-in Rust test reparses both outputs and asserts settings,
mapping, directory and SFO-identity equality after approved-root preflight.

GP4 files contain passcodes: output root is mode 0700; native/variant XML is 0600.
Do not print or commit XML. No passcode appears in `evidence.json`. Re-run only
the native comparison against an existing successful local run with:

```sh
PKG_TOOLS_GP4_REFERENCE_DIR=/private/reference-run \
  cargo test -p ps4-pkg --test gp4 pinned_reference_roundtrip -- --ignored
```

Executed 2026-10-31, Linux, same pin/SDK: **9 files / 4 directories**, native
generation → reference load/tree/write → native reparse/preflight; exact supported
settings/mappings retained. Comments/formatting/namespaces are not a lossless XML
claim. This neither builds a GP4 package nor establishes official-tool, custom
PlayGo, updates, NP/trophy/save or console support. Existing 27/27 package checks,
keyless corruption detection and 8-file/3-directory extraction still pass.

## PS3 container-plaintext oracle

`ps3.py` independently parses PS3 headers/records/SFO and decodes the data region
with OpenSSL AES-128-CTR (retail) or Python hashlib SHA-1 (debug). The format
baseline is RPCS3 revision `6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4`;
this source-derived oracle does not run the RPCS3 installer or transform SDAT.
It compares CLI inspection and every extracted path, size and SHA-256.
Temporary disk use is approximately the encrypted-data size; RAM is bounded.

```sh
cargo build --release -p pkg-cli
target/release/pkg-tools extract /path/to/game.pkg pkgs/ps3/extracted
TMPDIR=/tmp/opencode python3 tests/reference/ps3.py \
  /path/to/game.pkg pkgs/ps3/extracted target/release/pkg-tools \
  --manifest pkgs/ps3/reference.json
```

Use trusted fixtures; this oracle is not a hardened package reader. The optional
manifest destination must be new. Keep manifests and game contents under ignored
`pkgs/`. On 2026-10-15 the supplied retail fixture matched **310 files and 22
directories**, including all exposed headers, metadata packets and SFO records.
Debug has synthetic coverage only. `tests/fixtures/ps3-debug.hex` is a tiny
Python `struct`/`hashlib`-generated package, with one `PARAM.SFO` whose TITLE is
`Synthetic`; it contains no game data. It is also used by CLI/GUI unit tests.

## PS4 inspection oracle

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

Package-source authoring inventory is also available with
`cargo run -p pkg-cli -- fpkg preflight INPUT.pkg`. It is read-only, keeps the
normal extraction mapping unchanged, and does not print retained header/digest/NP/
keystone bytes. Native synthetic tests cover its byte retention and refusal rules;
no new independent package-source comparison has been executed. Existing extraction
comparisons below do not establish lossless rebuild or writer compatibility.

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
## PS3 RAP-less conversion oracle

`ps3-liberation.py` requires Python `cryptography` (test-only). Run against a
source PKG, its RAP, and the converted PKG:

```sh
python3 tests/reference/ps3-liberation.py SOURCE.pkg LICENSE.rap OUTPUT.pkg \
  target/release/pkg-tools
```

Checks transformed SELF sections/HMACs and the new header ECDSA signature;
transformed EDAT plaintext and hashes; package paths/content ID; unchanged
file sizes and first/last 64 KiB. Large unchanged files are sampled, not fully
hashed. Developer-key scanning can take several minutes in Python. No emulator
or console launch is performed. Fixtures and generated packages stay ignored.
