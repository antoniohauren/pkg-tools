# Native ZArchive writer (milestone 4)

Implemented and checked on Linux against upstream ZArchive commit
`965b66c8d67b6b7e30fd63b3b75aa91a99ff303b`, also pinned by the selected shadPS4.
Production archive creation is Rust-only; C++/libzstd are test-oracle dependencies.

```sh
cargo run --release -p pkg-cli -- pack INPUT_DIR OUTPUT.zar
```

The source directory's children become archive-root children. Destination must
be outside the source tree, with an existing parent directory. Source must remain
stable throughout packing: this is not a snapshot or a descriptor-relative,
race-resistant traversal of an adversarially changing filesystem. Symlinks and
special files encountered during traversal are rejected. Source bytes are not edited.

## Library contract

`zarchive::Writer::create(destination)` creates private sibling scratch storage.
Call `add_directory(path)` and `add_file(path, size, reader)` with parents first;
`reader` implements `Read`, must yield exactly `size` bytes, then EOF. Readers with
additional data must be explicitly bounded by the caller. Call consuming `finish()`
to publish. Any addition error poisons the writer; finalization cannot publish it.
`zarchive::pack_directory(source, destination)` implements the directory workflow.

Paths are relative UTF-8 with `/` separators. Empty, dot/dotdot, NUL, backslash,
colon, duplicate and ASCII-case-colliding components are rejected. Parent spelling
must match exactly. Non-ASCII bytes are preserved without Unicode normalization
or Unicode case folding. ASCII-folded byte ordering matches upstream.

**Component limit is 127 UTF-8 bytes**, despite the format's nominal 32767-byte
limit. The pinned reader's `GetName` uses `nameTable[nameOffset]`, rather than
`nameTable[nameOffset + 1]`, when decoding the extended length byte. Independent
testing confirmed 128/255-byte names fail enumeration. Emitting the nominal
two-byte encoding would therefore produce unreadable names. Revisit only when
the consumer's pinned reader changes; do not truncate names.

Entirely zero-payload trees are rejected because the pinned reader rejects an
empty chunk-index table. Empty files/directories alongside nonempty payload work.
No dummy payload or alternate encoding is introduced.

## Format, storage and publication

- Concatenated logical file stream, 64 KiB blocks, final block zero padding;
  independent `ruzstd::Fastest` frames, raw blocks when compression is not smaller.
- Big-endian 40-byte offset records, 8-byte alignment after compressed payload,
  length-prefixed names, breadth-first sorted 16-byte nodes, empty metadata tables.
- 144-byte footer and SHA-256 over the entire archive with hash field zeroed.
- Checked 48-bit logical range and pinned-reader name/tree/chunk-table limits.
- Payload buffers and chunk-index RAM are bounded. Offset records spill to a
  scratch file (40 bytes per logical MiB), then stream into the archive.
  Node/name/order metadata remains proportional to entry count and path lengths.
- Finalized archive is synced before same-filesystem `hard_link` publication.
  Publication is atomic and fails if any destination entry already exists,
  including a symlink or a file created during packing. Hard-link support is
  required. No overwrite fallback is used.
- Normal errors/drop remove scratch files. Process kill/power loss can leave a
  `.zarchive-PID-SERIAL` scratch directory; remove it only after its writer exits.
  Parent-directory crash durability is not promised; an error cannot expose a
  partial archive at the requested destination. Cleanup is best-effort.

## Executed verification

`tests/reference/check-zarchive.py` builds the unmodified pinned C++ reader,
creates a deterministic source tree and compares enumeration, sizes, every byte,
case-insensitive lookup and random reads (including EOF and chunk boundaries).
It independently checks footer SHA-256 and presence of raw/compressed chunks.

Linux runs passed: 18 files/2 directories, empty files/directories, nested trees,
65535/65536/65537-byte and multi-record payloads, UTF-8 names and 127-byte names.
`--large` passed with a sparse-generated 4 GiB + 65537-byte source (19 files),
including full byte comparison and subsequent file offsets beyond 4 GiB.
This is synthetic coverage, not a real large-game fixture.

Rust tests cover exact lengths, failed input after a stored chunk, poisoned
writers, path/case rejection, zero payload, footer integrity, spilled records,
symlink rejection and no-overwrite publication races/cleanup.

Release smoke measurement: 128 MiB input, half seeded noisy 64 KiB blocks and
half `abc12345` repetitions, produced 67,209,421 bytes in 1.027 seconds (~125 MiB/s).
Linux child `getrusage` peak RSS was 16,320 KiB. This local warm-cache synthetic
measurement is not a representative game benchmark or cross-platform guarantee.

Windows/macOS, hostile concurrent source mutation and shadPS4 recognition/runtime
remain unverified. Archive read compatibility does not establish game playability.

## PKG conversion

```sh
pkg-tools convert GAME.pkg Game.zar
pkg-tools convert GAME.pkg Game.zar --update UPDATE.pkg
```

The CLI uses `ps4_pkg::Game` entry readers directly, preserving the verified
application tree and restored `sce_sys` metadata. It does not extract a full
temporary directory. ZArchive scratch payload/index files still live alongside
the outputs. Progress reports entry counts and decoded byte totals.

Only the existing GD base/full-update extraction subset is accepted. The base
must have SFO category `gd`; optional update must have `gp`. Title/content IDs
must match between the pair, and each SFO content ID must match its PKG header.
The base title must be `CUSA` plus five digits and match its content-ID title
component. These are identity checks, not proof of game/runtime compatibility.
Delta, DLC, retail and unsupported PFS shapes retain extraction's rejections.

Output must end in lowercase `.zar`. Update output is the base output's stem
plus `-UPDATE.zar`, in the same directory. Files are not merged. Both packages
are opened/validated and both outputs checked before streaming. Both payloads
are streamed before publishing either archive. Each archive has atomic
no-overwrite publication; the pair is not one atomic filesystem transaction.
If update finalization/publication fails after base publication, the completed
base is retained and explicitly reported. Source packages are never removed.

Executed with both supplied local fixtures: upstream reader compared 4,583 files
and 1,483 directories against the previously verified extraction trees, including
every byte and random reads. This establishes archive content compatibility;
shadPS4 recognition, overlay mounting and game loading have not been run.
