# Independent inspection oracle

## Native source-backed base rebuild acceptance

### Additional newcrypt and retained-resource profile

After preparing the legacy synthetic source below, `check-rebuild-profile.py`
(Python `cryptography`/OpenSSL required) independently builds a **synthetic-only**
nonzero-seed newcrypt source, with paired encrypted NP records, padded 0x403
storage, trophy00 and all additional supported resources. No real NP/trophy
identity is generated. It authenticates all referenced outer blocks, rekeys
bottom-up, re-encrypts metadata against final offsets, and finalizes all hashes.
It also exercises version-0x3000 PlayGo header/SDK preservation. This source uses
the verified canonical general-digest recipe; it does **not** exercise unverified
modern System/PlayGo/Trophy or alternate MajorParam/Content recipes. A private
source requiring those recipes was safely rejected before scratch/publication.

```sh
python3 tests/reference/check-rebuild-profile.py prepare \
  /tmp/opencode/native-rebuild-new-setup/fixture/synthetic.pkg \
  /tmp/opencode/newcrypt-resource-source.pkg
target/debug/pkg-tools fpkg rebuild /tmp/opencode/newcrypt-resource-source.pkg \
  /tmp/opencode/newcrypt-native-output.pkg
python3 tests/reference/check-rebuild-profile.py verify \
  /tmp/opencode/newcrypt-resource-source.pkg /tmp/opencode/newcrypt-native-output.pkg
PKG_TOOLS_REBUILD_REFERENCE=/tmp/opencode/newcrypt-resource-source.pkg \
  cargo test -p ps4-pkg --test rebuild -- --include-ignored
```

Use new paths; no existing file is replaced. Acceptance checks every stored
container/PlayGo/general digest, exact retained licenses/NP/SFO/trophy/resources,
legacy destination flags, and every outer plaintext block HMAC including indirect
and inode blocks. Run the prepared pinned `reader/Extraction.dll` on source and
native output too; compare complete inner/resource manifests, excluding only
regenerated PlayGo. That independent reader omits NP records; the separate
Python CBC/padded-NP comparison covers them. No console, save or trophy-runtime
validation follows. The small synthetic HMAC walker supports one inode block and
single indirection only; do not use it as a private/large-package checker.

`check-native-rebuild.py` separates fixture preparation from acceptance of an
**actual native writer output**. It does not substitute reference generation for
native-writer evidence. Only its original bounded synthetic content ID is accepted;
do not supply games, private fixture packages or arbitrary external application trees.

```sh
python3 tests/reference/check-native-rebuild.py self-test
python3 tests/reference/check-native-rebuild.py prepare /path/to/dotnet-sdk/dotnet \
  /path/to/clean/pinned-LibOrbisPkg /tmp/opencode/native-rebuild-new-setup \
  target/debug/pkg-tools
```

Requires clean LibOrbisPkg `643477263b2644e0803e0f58b8726ea4e3f3b7d4`,
.NET SDK 8.0.425 and built native CLI. Preparation creates a private 0700 root,
`fixture/synthetic.pkg`, independent `source-readback.json`, and `source-tree/`.
The adapter's explicit **synthetic-only** zero-passcode mode permits source-backed
testing without saving/logging real passcodes or adding crypto constants. Default
`check-authoring.py` behavior still uses disposable random passcodes. Reference
checkout stays untouched; adapted PFSC source and reference binaries remain local.

Run the native source-backed writer separately using that source package/tree.
Once it produces a new package, supply its path directly (no inferred CLI command
or automatic writer fallback):

```sh
python3 tests/reference/check-native-rebuild.py verify /path/to/dotnet-sdk/dotnet \
  /tmp/opencode/native-rebuild-new-setup "$NATIVE_OUTPUT" \
  /tmp/opencode/native-rebuild-new-acceptance target/debug/pkg-tools \
  --inner-size 0x550000
```

Both output roots must be new. `--inner-size` is the native clear inner-image
logical length, not encrypted outer/PFSC/package length; `0x550000` matches this
fixture's minimum inner image. Change it only if the writer intentionally chooses
a different layout. Source package itself (including hard-link aliases) is refused
as native output; caller must still establish writer provenance, since copying a
reference package to another path cannot prove native emission.

Acceptance requires:

* Independent Python layout, every stored-entry/header/body/PFS/table/SC digest,
  exact default PlayGo DAT, manifest XML semantics, supported general digests, and
  every package-relative 64-KiB PlayGo SHA slot. Synthetic packages capped at 16 MiB.
* Every validation emitted by pinned `PkgValidator` returns **Ok**; **NoKey fails**,
  including fake-header equality and debug RIF signature checks. Results saved to
  `validation.json`; this is legacy fake-header validation, not Sony signing.
* Pinned reader independently decrypts/traverses source and native output. Exact
  namespace and complete size/SHA256 comparison covers every retained payload and
  extracted application resource, **including SFO and keystone**. Only the three
  regenerated PlayGo files may differ from source; their native bytes must pass
  the semantic/hash checks above. Native extraction then matches every independent
  native-output file/resource byte, including all three PlayGo files.
* Five disposable-copy corruptions fail their intended Python checks. Additional
  fake-header-signature corruption must pass keyless checks but fail exactly the
  pinned header-signature validation. Originals and existing outputs are preserved.

`evidence.json` records pins, adapter hashes, counts and explicit limits, never keys
or source-package fingerprints. Reference builder/validator/reader share lineage;
Python keyless/PlayGo checks do not. Embedded PFS reader authenticates its header,
**not every block HMAC**; separate outer-image oracle below does not automatically
establish all-block authentication for this rebuilt package. No >4-GiB, install,
launch, firmware/GoldHEN, NP/trophy identity, save or update compatibility follows.

Executed 2026-10-31: comparison self-tests and six existing verifier regression
tests passed; preparation at `/tmp/opencode/native-rebuild-acceptance-2` passed
**27/27 pinned validations**, 219 Python layout/hash checks plus DAT/XML/general
checks, and all **8 files / 3 directories** matched native extraction. Explicit
validator mode also passed on the first prepared source. The second setup verified
the known synthetic passcode by pinned readback, and all six disposable-copy
corruption checks passed as harness regression against its reference source.
Native-output verification
remains pending until a writer output is supplied; preparation is not native
full-package acceptance. Upstream builds emitted ten known obsolete-API/lowercase
warnings per adapter, no errors.

### Runnable fixture gate

**The prepared `eboot.bin` is a non-executable sentinel. It CANNOT launch and its
package must never be called PS4-ready.** No runnable fixture/toolchain was found
in the limited local search of `/usr/local`, accessible `/opt`, and project paths;
`/opt/containerd` was inaccessible. Ignored `pkgs/` was not inspected.

Official open-source starting point, inspected 2026-10-31:
[OpenOrbis toolchain](https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain) documents
`samples/hello_world`, clang/lld, toolchain libraries/stubs, `create-fself`, and
`OO_PS4_TOOLCHAIN`. Source checkout alone lacks built toolchain libraries/binaries;
the official README recommends release/toolchain setup. No release binary, game
or arbitrary executable was downloaded, and no toolchain was installed. User must
choose/build a permitted runnable source package separately, preserve its license
and identity, then explicitly perform console install/launch/save tests. This
synthetic-only harness is deliberately not an arbitrary homebrew acceptance tool.

## Keyless container generation

`ps4-pkg` integration tests exercise default PlayGo DAT/XML and keyless digest
generation without a package writer. Export only original opaque synthetic bytes
(not a valid PKG) for independent Python/stdlib checks; use a fresh nonexistent path:

```sh
PKG_TOOLS_KEYLESS_SYNTHETIC_OUTPUT=/tmp/opencode/native-keyless-container.bin \
  cargo test -p ps4-pkg --test container keyless_synthetic_finalization
python3 tests/reference/check-container.py /tmp/opencode/native-keyless-container.bin --inner-size 0x50000
```

The Python checker independently validates exact default 416-byte DAT, manifest
semantics, supported general-digest flags/slots/SFO text serialization, plus existing
layout, stored-entry, body/table/SC, header, PFS and every PlayGo SHA-slot check.
Input capped at 16 MiB. Synthetic test buffers are not native streaming behavior.

The existing ignored `pinned_reference_container_layout` test now also compares
DAT/general/SHA records and all supported hash values against pinned-L output:

```sh
PKG_TOOLS_CONTAINER_REFERENCE=/path/to/synthetic/fixture/synthetic.pkg \
  cargo test -p ps4-pkg --test container pinned_reference_container_layout -- --ignored
```

Executed 2026-10-31: Rust comparison against existing
`base-container-oracle-check-2` synthetic fixture passed; Python reported 219
layout/hash checks plus DAT/XML/general checks on that reference (inner size
`0x550000`), and 134 plus DAT/XML/general checks on native opaque bytes (inner
`0x50000`). Native tests also check short reads/EOF, cancellation during a block,
wrong lengths, write failures, malformed SFO/identity, optional ATTRIBUTE2, padding
coverage, SC truncation and final header dependencies.
No new reference package build or console/graphical/private-fixture test performed.
No keys, signatures, licenses, metadata encryption, publication or installability
are supplied/established by this check. No new crypto dependency or numeric key.

## Synthetic container crypto vectors

`container::encrypt_metadata` and `public_rsa_wrap` are low-level, bounded legacy
FPKG encoders, not a package writer or authentic signing API. New synthetic tests
use an original disposable RSA pair's public half, never package wrapping constants.
No private half is stored. Export requires a new path (no overwrite):

```sh
PKG_TOOLS_CONTAINER_CRYPTO_OUTPUT=/tmp/opencode/container-crypto-new.bin \
  cargo test -p ps4-pkg independent_padding_public_wrapping_and_metadata_vectors
python3 tests/reference/check-container-crypto.py /tmp/opencode/container-crypto-new.bin
```

Python independently computes exact padding/public exponentiation with its own
built-in MT19937, hashlib and integer pow, and all four metadata CBC vectors with
OpenSSL-backed cryptography. Cases distinguish D[2]/D[3], changed final offsets and
flags, IV/key halves and zero-padding/declared lengths. Rust also checks malformed
keys/record lengths, unsupported IDs/indices/algorithm and actual planned record
sizes. No streaming/I/O API introduced; synthetic export uses create-new.

For pinned L comparison, reuse clean reference pin and the external
`PFSCReader.net8.cs` adaptation from the authoring harness (paths below illustrative):

```sh
/path/to/dotnet-sdk/dotnet build tests/reference/Authoring.csproj \
  -p:ReferenceRoot=/path/to/clean/pinned-LibOrbisPkg \
  -p:ReferencePfsc=/path/to/existing-oracle/reader/PFSCReader.net8.cs \
  -p:BaseIntermediateOutputPath=/tmp/opencode/container-crypto-obj-new/ \
  -o /tmp/opencode/container-crypto-oracle-new
/path/to/dotnet-sdk/dotnet /tmp/opencode/container-crypto-oracle-new/Authoring.dll \
  --crypto /tmp/opencode/container-crypto-new.bin
```

Executed 2026-10-31: Rust, Python and pinned L exact comparisons passed. External
.NET SDK 8.0.425 needed (`/usr/bin/dotnet` here has runtime only); upstream generated
10 known obsolete-API/lowercase-name warnings, no errors. No new package build,
private/game input, secret signing, graphical/reference-extraction rebuild or
console/emulator check. Full ENTRY_KEYS/license/fake-header integration remains
separate. Legacy deterministic type-2 padding leaks equality; RSA timing advisory
does not approve private signing. No dependencies/features/lockfile changed.

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
  IDs, GD base flags and physical size. It also checks the bounded layout and
  package-relative PlayGo digests detailed below. Maximum accepted package is
  16 MiB, with 64 KiB hashing/copy buffers. Five disposable-copy mutations must
  fail their intended checks: header, body padding, first PFS block, final PFS byte,
  and table reserved bytes. No corruption touches the original fixture.
* Native `container::BaseContainerLayout` plans the generated reference image and
  resource sizes, then its entire serialized entry table, names, body/PFS boundary
  and package size must match the reference bytes. The harness runs the opt-in
  `pinned_reference_container_layout` Rust integration test automatically. This
  checks planning against independent output, not native package emission.
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

### Base container acceptance checks (2026-10-31)

These are the **pinned L GD builder profile**, not general PS4 validity rules or
native-writer acceptance. Python reads serialized bytes without importing Rust
layout code. Source evidence at the pin above:

* `PKG/PkgWriter.cs:28-115`: big-endian header field locations.
* `PKG/PkgBuilder.cs:246-266,345-465`: body starts at `0x2000`, mirrored entry
  counts, **SC count 6**, generated records/flags/key indices, physical system
  allocation order `10,20,80,100,1,200` (hex), ID-sorted table, 16-byte entry
  alignment and `0x80000` body/PFS alignment. The verifier does not hardcode
  `0x2a80`: METAS must describe the actual table location and `count*32` length.
* `PKG/Entry.cs` (`MetaEntry.Write`, `NameTableEntry`): six BE32 fields followed
  by eight zero bytes; name offsets reference ASCII NUL-terminated name starts,
  including the initial empty name.
* `PKG/PkgBuilder.cs:151-203`: stored-byte entry digests indexed by sorted table
  position, zero DIGESTS self slot, whole padded-body hash, whole digest-table
  hash; SC1 concatenates ENTRY_KEYS/IMAGE_KEY/GENERAL_DIGESTS/full METAS/DIGESTS,
  while SC2 omits DIGESTS and includes **only `sc_entry_count*32` METAS bytes**.
  PlayGo SHA uses the first four SHA256 bytes of each stored 64 KiB PFS block,
  indexed by **package-relative** block number, with zero pre-PFS slots.

Before hashing, Python checks all ranges against actual bounded file size, count
limits, record padding, unique sorted IDs and required system/license/reserved/
SFO/PlayGo records. Entries must lie inside body, be aligned and nonoverlapping;
first six physically allocated records must have the order above. Fixed generated
sizes/flags/key indices, SC1 length, name boundaries/terminators and PlayGo length
are checked. Body end must equal PFS start, PFS must contain whole 64 KiB blocks
and end at EOF, and promote/mount/package sizes must agree. Table self-location is
validated, not treated as a separate overlapping allocation. No contiguity or
name-sorted allocation requirement is invented for later optional resources.

`check-authoring.py --self-test` runs six `test-authoring.py` tests (including
mutation subtests) using only Python stdlib.
Its original 1 MiB **opaque/keyless** fixture has no valid license, SFO or PFS;
it tests the verifier, not package installability. Structural mutation subtests
cover huge/truncated ranges, count mismatch, missing/duplicate IDs, physical
ordering, table identity, overlap/alignment, flags, name boundaries and padding.
Targeted digest mutations repair enclosing body/header hashes where needed so
entry/table/self-slot/SC failures cannot be masked by an earlier checksum failure.
PlayGo tests repair all other keyless hashes, then reject stale PFS block slots
and nonzero pre-PFS slots. This small test fixture construction is not an
independent writer proof; the external pinned builder run is the format evidence.

Executed full oracle again on 2026-10-31, Linux/.NET SDK 8.0.425: all 27 upstream
validations Ok; strengthened Python acceptance and five external-copy corruption
checks pass; 8 files / 3 directories match native extraction; GP4 round trips pass.
Only existing upstream obsolete-API/lowercase-type warnings occurred. Local run
root: `/tmp/opencode/base-container-oracle-check-2` (private generated artifacts).
The native layout comparison also passed against this generated fixture. To rerun
that check alone, set `PKG_TOOLS_CONTAINER_REFERENCE` to its `fixture/synthetic.pkg`
and run `cargo test -p ps4-pkg --test container -- --ignored`.

Still not verified here: fake-header RSA construction or metadata decryption by
an independent crypto implementation, general-digest semantic inputs, debug-RIF
or keystone encoder provenance/known answers, native full-PKG emission, NP/trophy,
updates/remarry, >4 GiB or actual console install/launch/save compatibility. The
separate outer-image oracle above covers synthetic all-block HMAC/XTS; this
keyless container verifier does **not** authenticate/decrypt its embedded PFS.
Crypto distribution approval remains unresolved. No new crypto constants or
dependencies are added; no external reference sources are modified.

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
