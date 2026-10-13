# PKG Tools

Library-first Rust package tools. PS4 header/SFO inspection and streaming FPKG
base/full-update extraction are implemented. Extraction is verified on Linux
against two local fixtures; see [coverage and format decisions](docs/extraction.md).

```sh
cargo run -p pkg-cli -- inspect INPUT.pkg
cargo run -p pkg-cli -- inspect INPUT.pkg --json
cargo run -p pkg-cli -- inspect PARAM.SFO --json
cargo run --release -p pkg-cli -- extract INPUT.pkg OUTPUT_DIR
```

Inputs are detected by magic, not filename. Rust 1.89 or newer is required;
current checks used Rust 1.99 on Linux. `psf` is standard-library-only; `ps4-pkg`
uses pure-Rust crypto/compression and safe Unix filesystem calls through `rustix`.
The CLI uses `serde_json`. [Dependency decisions](docs/dependencies-and-fixtures.md).

## Libraries

- `psf::parse(&bytes)` reads SFO 1.0/1.1, retaining typed values, unknown formats,
  original bytes and capacity padding. Keys and text remain byte slices;
  callers choose whether to decode UTF-8. Integers preserve all 32 bits.
- `ps4_pkg::Package::open(reader)` accepts `Read + Seek`, exposes `header()` and
  container `entries()`, and reads plaintext bytes with `read_param_sfo()`.
   Parse those bytes with `psf::parse`. Container entries are not PFS files.
- `package.open_game()` consumes the package and returns an application tree.
  `game.entries()` enumerates `FileEntry` paths, kinds and sizes;
  `game.read_entry(index)` returns a borrowed streaming `Read + Seek` reader.
  `game.extract(output_dir)` writes the application layout, including `sce_sys`.

```rust,ignore
let mut package = ps4_pkg::Package::open(std::fs::File::open("input.pkg")?)?;
if let Some(bytes) = package.read_param_sfo()? {
    let metadata = psf::parse(&bytes)?;
    println!("{:?}", metadata.get(b"TITLE"));
}
let mut game = package.open_game()?;
game.extract("output-directory")?;
```

Errors distinguish malformed data, unsupported formats/versions, resource limits,
unavailable decryption material, and I/O failures. Missing SFO is separate from
encrypted SFO. The CLI returns success for valid header inspection with missing
or encrypted SFO, explicitly reports that status, and returns nonzero for parse,
I/O, unsupported-input, or argument errors. Diagnostics go to stderr.

JSON includes header fields, container records and SFO entries. Numeric enums
remain numeric; raw SFO data, padding and keys have hex fields. Invalid UTF-8
has a null decoded value rather than lossy substitution. `fpkg_status` remains
`unverified`: header inspection does not prove fake-key recovery or authenticity.

## Validation and limits

- Extraction requires a **new** output directory with existing parents. It
  rejects symlinks in the destination path, traversal, special nodes, portable
  filename hazards, ASCII-case collisions and duplicate files. No merging or
  replacement. Output failures leave `.pkg-tools-incomplete` and return an error
  naming the partial tree; an interrupted tree must be removed before retrying.
  Sources are read-only. Disk extraction currently requires Unix; streaming
  readers are platform-independent but Windows/macOS remain unverified.
- Extraction supports nested 64 KiB D32/S32 PFS and indexed zlib/raw PFSC.
  Payload buffers and on-demand block indexes are bounded independently of
  payload size. Tree memory scales with paths/inodes, capped at one million
  entries and 64 MiB of path bytes; paths are ASCII, at most 4,096 bytes/128
  components, with 255-byte components. Individual directory data is capped
  at 64 MiB. See the format document for unsupported variants.
- Fake RSA unwrap, DK3 digest, outer signed-PFS header HMAC, bounds and zlib
  checksums are checked. **Not full payload/signature authentication.** Extraction
  preserves decoded contents; it does not decrypt SELF/EDAT or patch executables.
- Complete PS4 inputs only; declared package length must match input length.
  Header, entry table, body, mount image, PFS and container data ranges must fit.
  Duplicate container IDs and entries overlapping the header are rejected.
- SFO tables must be ordered and fit; used lengths must fit capacities, integer
  values must occupy four bytes, and keys/text must have bounded NUL terminators.
  Duplicate/empty keys and overlapping nonempty value capacities are rejected.
- Inspection limits: 65,536 container records, 65,536 SFO records, 16 MiB SFO,
  1,024-byte keys. Limits are explicit implementation policy, not format maxima.
  Value bytes are borrowed by the SFO parser. Package payload is never buffered;
  memory grows with bounded metadata, including its JSON representation.
- Unknown PS4 content types/flags stay inspectable as raw numbers. No universal
  PS4 header version field is assumed; SFO versions are checked explicitly.
  Name-table offsets are exposed but names are not resolved or used as paths.

## Verification

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Twenty-five workspace tests cover parsing, key recovery, crypto known answers, nested
PFS/PFSC, direct/single/double-indirect reads, >4 GiB virtual files/offsets,
corruption, path collisions, symlinks, overwrite refusal and incomplete output.
Both local PS4 base/full-update fixtures match reference paths, sizes and SHA-256:
4,583 files and 1,483 directories total. Header/SFO comparisons also pass. Reproduction:
[reference comparison](tests/reference/README.md).

PS3 and ZArchive remain later milestones. DLC, retail extraction, delta patches,
64-bit PFS inodes and per-file PFS compression are unsupported. No emulator or
Windows/macOS compatibility claim follows from extraction results.

See [plan](PLAN.md), [compatibility targets](docs/compatibility.md), and
[dependency/fixture notes](docs/dependencies-and-fixtures.md).
