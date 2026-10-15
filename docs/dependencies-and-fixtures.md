# Dependency shortlist and fixture strategy

Research date: 2026-10-13. Format requirements and reference pins belong in
[compatibility.md](compatibility.md). This is a shortlist, not a dependency lock
or a blanket claim of package support. Milestone 3 selects the extraction
dependencies below; the later candidate table retains historical research.

## Milestone 6 PS3 dependency selection

`ps3-pkg` reuses `aes` **0.9.3** and adds RustCrypto `sha1` **0.11.0**, defaults
disabled, for the debug format's SHA-1-derived stream. The reviewed crate is
MIT OR Apache-2.0, MSRV 1.85; its `digest` 0.11, `cfg-if` and `cpufeatures`
dependencies are already resolved by the workspace. No native crypto dependency
is introduced. Retail random reads compose AES blocks with the format's
big-endian counter, avoiding an additional CTR dependency. SHA-1 is a format
requirement, not a choice for new integrity protection.

`pkg-fs` now owns the already-selected Unix `rustix` dependency and shares
descriptor-relative output creation and portable filename policy between PS3
and PS4. Production dependencies remain independent of reference tooling;
OpenSSL is used only by the optional PS3 test oracle.

## Milestone 4 dependency selection

`zarchive` selects `ruzstd` **0.9.1**, defaults disabled, `std` only, and the
already-selected `sha2` **0.11.1** with defaults disabled. The previously reviewed
MIT-licensed pure-Rust encoder adds no normal transitive dependencies. Only its
implemented `Fastest` mode is used. Full archive tests now pass against the
pinned upstream reader; [writer results](zarchive.md) include synthetic throughput
and >4 GiB readback. No native compression dependency enters production.
An exact-version OSV query for `ruzstd` 0.9.1 on 2026-10-15 returned no advisories;
this supplements the prior manifest/license review, not a source security audit.

## Milestone 3 extraction dependencies

`ps4-pkg` selects the reviewed pure-Rust versions/features from the table below:
`aes` 0.9.3, `cbc` 0.2.1 (`block-padding`), `xts-mode` 0.6.0, `sha2` 0.11.1,
`hmac` 0.13.0, `rsa` 0.9.10 (`std`, `u64_digit`) and `flate2` 1.1.10
(`rust_backend`), all defaults disabled. No CTR, SHA-1 or Zstandard dependency
is added for this milestone. CBC uses NoPadding; a partial container tail uses
the AES primitive for the format's CFB remainder. RSA is restricted to the
two public fixed key pairs and offline package reads, per the advisory below.

For safe Unix output, `rustix` **1.1.5**, defaults disabled, features `std,fs`,
provides descriptor-relative filesystem calls and `O_NOFOLLOW` without unsafe
code in this workspace. Standard-library path checks cannot provide equivalent
race resistance. Maintained by Bytecode Alliance; MSRV 1.65; license
Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT. Its reviewed manifest enables
`bitflags` and, on this Linux target, `linux-raw-sys`; other Unix targets can use
libc/errno. This explicitly accepts platform system-call bindings, not a native
crypto/compression implementation. No C/C++ build or OpenSSL enters production.

Actual workspace resolution contains **73 external versions**, including optional
and target-specific packages. Manifest/license review found permissive licenses:
MIT/Apache-2.0 variants, BSD-3-Clause, 0BSD/Zlib, Unlicense, Unicode-3.0 and the
rustix LLVM exception. OSV batch query for all 73 exact versions on 2026-10-13
returned only **RUSTSEC-2023-0071** for RSA. Its offline/public-key restriction
remains necessary; this is a dependency metadata/advisory review, not a source
security audit. `Cargo.lock` records the actual resolution.

## Milestone 2 dependency selection

`psf` and `ps4-pkg` use only the standard library. `pkg-cli` selects
`serde_json` **1.0.154**, defaults disabled, `std` enabled, rather than hand-written
JSON escaping. It is maintained in serde-rs/json, licensed MIT OR Apache-2.0,
and declares Rust 1.71. Workspace MSRV is 1.89; executed checks used 1.99.

Actual normal/build graph has five external crates: `serde_json`, `serde_core`
1.0.229, `memchr` 2.8.3, `itoa` 1.0.18, `zmij` 1.0.23. No native dependency or
derive/proc-macro feature is enabled. `Cargo.lock` also resolves optional serde/
derive support, for eleven external versions total. Manifest/license review:
MIT/Apache-2.0 except `memchr` (Unlicense OR MIT), `zmij` (MIT), and
`unicode-ident` ((MIT OR Apache-2.0) AND Unicode-3.0). An OSV batch query for all
eleven locked versions on 2026-10-13 returned no matching advisories. This is
a snapshot and metadata review, not a source/security audit.

## Dependency decisions

Use standard-library checked reads and endian conversion for PSF/package/PFS/ZAR
structures. Add dependencies only to crates that actually need their primitives.
PSF and initial plaintext header inspection need no cryptographic dependency.

Versions below were inspected through the versioned crates.io manifests and
resolved together in a disposable Cargo project. Versions are research pins;
recheck advisories and commit the actual workspace lockfile when implementing.

| Candidate | Intended use | Features to enable (defaults off) | License; published |
| --- | --- | --- | --- |
| [`aes` 0.9.3](https://crates.io/crates/aes/0.9.3) | AES primitive for package and filesystem encryption | None | MIT OR Apache-2.0; 2026-08-28 |
| [`cbc` 0.2.1](https://crates.io/crates/cbc/0.2.1) | PS4 entry/image CBC processing | `block-padding`, explicitly select `NoPadding` where format requires it | MIT OR Apache-2.0; 2026-05-20 |
| [`ctr` 0.10.1](https://crates.io/crates/ctr/0.10.1) | PS3 retail data stream | None; validate counter endianness and byte-offset seeking against reference | MIT OR Apache-2.0; 2026-05-20 |
| [`xts-mode` 0.6.0](https://crates.io/crates/xts-mode/0.6.0) | PS4 PFS sectors | None; never enable `openssl_tests` or `benchmarks` in production | MIT; 2026-05-05 |
| [`sha2` 0.11.1](https://crates.io/crates/sha2/0.11.1) | PS4 derivation/integrity, ZAR SHA-256, fixture hashes | None | MIT OR Apache-2.0; 2026-10-12 |
| [`hmac` 0.13.0](https://crates.io/crates/hmac/0.13.0) | PS4 PFS key derivation/integrity | None | MIT OR Apache-2.0; 2026-03-29 |
| [`sha1` 0.11.0](https://crates.io/crates/sha1/0.11.0) | PS3 debug stream, if that variant is implemented | None | MIT OR Apache-2.0; 2026-03-27 |
| [`rsa` 0.9.10](https://crates.io/crates/rsa/0.9.10) | PS4 known fake-key RSA unwrap, PKCS#1 v1.5 encryption padding | `std`, `u64_digit`; no OAEP hash feature or PEM parser | MIT OR Apache-2.0; 2026-01-06 |
| [`flate2` 1.1.10](https://crates.io/crates/flate2/1.1.10) | PS4 PFSC zlib/DEFLATE blocks | `rust_backend` | MIT OR Apache-2.0; 2026-08-28 |
| [`ruzstd` 0.9.1](https://crates.io/crates/ruzstd/0.9.1) | First-choice Zstandard encoder to evaluate for ZAR | `std`; `CompressionLevel::Fastest` | MIT; 2026-10-11 |

Recent releases establish release activity, not independent security review.
RustCrypto owns AES, CBC, CTR, SHA, HMAC and RSA upstreams; `xts-mode` and
`ruzstd` have separate maintainers. Primary repository URLs and declared MSRVs
are in each linked crate manifest. This set requires at least Rust 1.89 because
of `aes`; do not silently pick an older toolchain target.

### Resolved transitive footprint

`cargo metadata --format-version 1` and `cargo check --quiet` succeeded on Linux
with the exact ten candidate versions above, default features disabled, and
features listed in the table. Resolution contained 62 external package versions
(including target-specific/build dependencies), not 62 runtime libraries:

- AES/CBC/CTR/XTS share `cipher` 0.5.2, `inout` 0.2.2,
  `crypto-common` 0.2.2 and `hybrid-array` 0.4.15. CPU detection uses
  `cpufeatures` 0.3.1 and AES also uses `cpubits` 0.1.1.
- SHA/HMAC share `digest` 0.11.3. RSA 0.9.10 still pulls `digest` 0.10.7
  and `generic-array` 0.14.7: two digest generations are expected.
  If PS3 debug support stays deferred, omit the direct SHA-1 0.11 dependency.
- RSA is the largest subtree: `num-bigint-dig` 0.8.6, `num-integer`,
  `num-traits`, `num-iter`, `rand`/`rand_chacha`/`rand_core`/`getrandom`,
  `pkcs1`/`pkcs8`/`der`/`spki`, `signature`, `subtle`, `zeroize`, and their
  support crates. Turning PEM off does not eliminate ASN.1 dependencies.
- `flate2` selects `miniz_oxide` 0.9.1, `adler2` 2.0.1,
  `simd-adler32` 0.3.10 and `crc32fast` 1.5.2. No `libz-sys`, OpenSSL or
  native compression build entered this resolution.
- `ruzstd` with only `std` has no normal external dependencies. `hash`
  adds `twox-hash`, unnecessary for emitting checksum-free independent frames;
  `dict_builder` adds `fastrand`, unnecessary for ZAR chunks.
- Transitive license declarations were inspected: predominantly MIT/Apache-2.0,
  plus BSD-3-Clause (`subtle`), MIT alternatives for BSD-2-Clause (`zerocopy`),
  0BSD/Zlib alternatives for Adler/miniz, Unicode-3.0 alongside MIT/Apache-2.0
  for `unicode-ident`, and permissive alternatives for target-specific `wasi`.
  Final notices must follow the actual lockfile, not this summary.

Sources: version-specific registry metadata at
`https://crates.io/api/v1/crates/NAME/VERSION/dependencies`, published
`Cargo.toml` files, and local Cargo feature resolution. This was a manifest and
license-declaration review, not an audit of all transitive source code.

**RSA caveat:** [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
still affects 0.9.10 (RSA timing leakage; no patched version listed). Conditional
acceptance is limited to offline operations with already-public fake-package
keys. Do not expose private-key decryption as a network service or treat this
choice as approval for secret user-supplied keys. Revisit if those requirements
change. An [OSV batch query](https://google.github.io/osv.dev/api/#osv-api)
of the initial 65-package resolution returned only this advisory on 2026-10-13.
Source research then established PKCS#1 v1.5 rather than OAEP; removing RSA's
unneeded SHA-1 feature reduced the final set to 62, all included in that scan.
Repeat against the actual workspace lockfile; this snapshot is not a guarantee
that the dependencies are vulnerability-free.

### Pure-Rust Zstandard experiment

`ruzstd` is no longer decoder-only. Its
[encoding API](https://docs.rs/ruzstd/0.9.1/ruzstd/encoding/index.html) exposes
`compress_to_vec` and reusable `FrameCompressor`. In 0.9.1, `Fastest` and
`Uncompressed` are implemented; `Default`, `Better` and `Best` are explicitly
unimplemented in [the source](https://docs.rs/ruzstd/0.9.1/src/ruzstd/encoding/mod.rs.html).
The encoder API does not return an I/O error result. Feed a bounded in-memory
block and collect an in-memory result; perform actual file I/O outside it with
normal error propagation.

Experiment performed in `/tmp/opencode/pkg-tools-dependency-review` (temporary,
not a repository artifact):

1. Encode lengths 0, 1, 65,535 and 65,536 using `Fastest`, once as repeated
   `0x2a` bytes and once as xorshift32 noise (seed `0x12345678`, shifts 13/17/5,
   emit low byte after each update).
2. Decode each resulting frame through system `libzstd` 1.5.7
   `ZSTD_decompress`; assert returned length and exact bytes.
3. All eight passed. Encoded sizes for repeated input: 9, 10, 10, 10 bytes;
   for noise: 9, 10, 65,544, 65,545 bytes.

This validates a narrow frame-level compatibility case only. It does not test
ZAR headers, chunk tables, archive hashing, random access, compression speed or
shadPS4. Uncompressible blocks can grow; implement the upstream ZAR raw-block
rule rather than assuming every frame fits its input length. Before selection
is final, retain an automated upstream-reader test and measure representative
64 KiB block throughput/ratio and memory use.

Native fallback, **not selected**: [`zstd` 0.14.2](https://crates.io/crates/zstd/0.14.2)
(BSD-3-Clause), through `zstd-safe` 8.1 and native `zstd-sys`. Defaults enable
legacy formats, arrays and dictionary building. Only consider this with an
explicit native-dependency decision if pure Rust fails interoperability or
practical performance. Its complete native build/license graph has not been
reviewed here.

## Fixture inventory and acquisition

The workspace initially contained only `PLAN.md`. During research the user
supplied a PS4 base and patch under `pkgs/` (two files observed). Both have PS4
container magic `7f434e54`; full-input SHA-256 fingerprints and sizes are recorded
in private `pkgs/inventory.json`. `/pkgs/` is Git-ignored, including that inventory.
No game package was downloaded. Header/table and plaintext SFO comparisons now
pass for both candidates; private results and SFO SHA-256 are recorded under
`pkgs/reference-inspection/`. Extraction, fake-key validation, expected extracted
file hashes were pending at acquisition. Milestone 3 now verifies fake-key
recovery, outer PFS header HMAC and all decoded file hashes for both fixtures;
see [extraction results](extraction.md). Emulator checks remain pending.

Rust/Cargo, CMake, Ninja and a C++ compiler are available. For milestone 2,
.NET SDK 8.0.425 was installed in `/tmp/opencode/dotnet` and used to compile an
adapter with unmodified inspection-related LibOrbisPkg sources. Reproduction
and results: [reference comparison](../tests/reference/README.md). No emulator
run was attempted.

Required private corpus, matched to the support targets in `compatibility.md`:

| Fixture | Purpose | Current status |
| --- | --- | --- |
| PS4 base FPKG, known fake-key path | Header/SFO, nested PFS/PFSC, extraction and base ZAR | Base extraction/hash comparison passed; ZAR pending |
| PS4 base with large file (>4 GiB), mixed compressibility | 64-bit offsets, bounded memory, throughput | Missing |
| PS4 update and its exact matching base | Identify standalone versus base-dependent patches; rejection/layout policy | Full-update extraction/hash comparison passed; runtime pairing unverified |
| PS4 DLC with data and entitlement-only DLC | Distinguish package contents and archive discovery limitations | Missing; not a support claim |
| PS3 finalized retail PS3-target package | First PS3 extraction target | Missing |
| PS3 debug and PSP/Vita/other-target samples | Classification and unsupported-variant rejection | Missing; not support targets unless matrix says otherwise |

For each supplied fixture, create a **private** manifest with: opaque fixture ID,
input byte length and SHA-256; package platform/variant/content ID/category;
expected SFO typed values; reference repository/revision, build environment and
exact extraction invocation; sorted output paths with entry kind, byte length
and SHA-256; expected acceptance or rejection. Include raw SFO bytes/hash so a
reference tool's display formatting cannot hide parser errors. Do not put local
paths, title-specific metadata or game hashes into public fixture files by
default.

Use SHA-256 of full bytes, streamed in fixed-size buffers; record relative paths
with `/` separators. Do not hash only compressed ciphertext or compare file
counts. Capture case, empty files, empty directories and symlinks separately;
never traverse symlinks while making the manifest. Record reference failures
instead of accepting incomplete extraction as expected output.

For PS4, compare both logical game-tree output and package metadata copied into
`sce_sys`; record any explicit mapping/exclusion. For archive checks use the
pinned **upstream ZArchive reader**, not the future Rust implementation's own
reader. Emulator recognition and successful title loading are separate results.

## Repository-safe synthetic corpus to build with implementation

No synthetic fixture is being represented as a real-game interoperability test.
Create small generated inputs alongside each parser, with reproducible seeds:

- PSF: string/integer/binary/unknown type, empty values, capacity versus used
  length, duplicate keys, missing terminators, invalid table ranges, truncation.
- Package tables: header magic/version, mixed endian fields, overflowed
  offsets/counts, entries beyond EOF and malformed encryption metadata.
- PFS/PFSC: directory/inode/block boundaries, compressed/raw blocks,
  inconsistent decompressed sizes, cycles and invalid block references.
- ZAR directory trees: empty archive/files/directories, nested paths, lengths
  65,535/65,536/65,537 and multi-chunk files, compressible and seeded noisy data.
  Exercise random reads spanning chunk/file boundaries through upstream reader.
- Extraction paths: `..`, absolute paths, separators, NUL, case collisions,
  destination symlink escape, duplicate names and preexisting outputs.
- Sparse/seekable generated data for >4 GiB offset arithmetic; use a real large
  fixture separately for end-to-end memory/performance claims.

Only commit original synthetic data or material with an explicit redistribution
license/provenance. A publicly downloadable game is not automatically a
redistributable test fixture. Corruption cases should derive from synthetic
inputs or stay in the private corpus.

## Remaining gates

- Base/patch extraction manifests and crypto known-answer checks now pass.
  Obtain remaining fixture classes and provenance before extending coverage.
- Resolve pure-Rust compression performance and full upstream-reader validation.
- Extraction lockfile/advisory review is complete for the recorded snapshot;
  Windows/macOS checks and broader large-file performance remain pending.
