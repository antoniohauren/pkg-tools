# PKG Tools

Library-first Rust package tools with a CLI and a native GNOME application.
PS3 retail/debug PKG inspection/extraction and PS4 FPKG inspection/extraction
are implemented. PS3 retail extraction is checked against one local fixture;
debug has synthetic coverage. PS4 extraction is verified against two local
fixtures. See [PS3 support](docs/ps3.md) and [PS4 coverage](docs/extraction.md).

```sh
cargo run -p pkg-cli -- inspect INPUT.pkg
cargo run -p pkg-cli -- inspect INPUT.pkg --json
cargo run -p pkg-cli -- inspect PARAM.SFO --json
cargo run --release -p pkg-cli -- extract INPUT.pkg OUTPUT_DIR
cargo run --release -p pkg-cli -- pack INPUT_DIR OUTPUT.zar
cargo run --release -p pkg-cli -- convert GAME.pkg Game.zar
cargo run --release -p pkg-cli -- convert GAME.pkg Game.zar --update UPDATE.pkg
```

`inspect` and `extract` accept PS3 and PS4 packages. Inputs are detected by magic,
not filename. Rust 1.89 or newer is required;
current checks used Rust 1.99 on Linux. `psf` is standard-library-only; `ps4-pkg`
uses pure-Rust crypto/compression and safe Unix filesystem calls through `rustix`.
The CLI uses `serde_json`. [Dependency decisions](docs/dependencies-and-fixtures.md).

Native Rust ZArchive writing is available through `pack` and `zarchive::Writer`.
It streams files, spills chunk indexes to disk and publishes finalized output
without overwriting. Pinned upstream-reader checks include random reads and a
synthetic >4 GiB file. Names must be UTF-8, at most 127 bytes per component;
entirely empty-payload trees are unsupported. See [writer contract](docs/zarchive.md).

`convert` streams a supported PS4 base FPKG directly into ZAR. Optional `--update`
creates sibling `Game-UPDATE.zar`, after checking base/update categories and
matching title/content IDs. Keep both files together for shadPS4's update overlay.
No extracted temporary tree is needed; source PKGs remain untouched. Existing
outputs are rejected. Both payloads are prepared before publication, but two-file
publication is not atomic: if update finalization fails, the completed base stays
and the error reports its location. See [conversion checks](docs/zarchive.md#pkg-conversion).

## GNOME application

`pkg-gtk` provides a native Rust GTK4/libadwaita interface for PS3 and PS4, authored in
Blueprint. Overview shows game artwork, title, title ID, application version,
game/patch type, package size, content ID and source. **All Info** in the
hamburger menu opens a modal dialog containing headers,
SFO metadata and container records. Binary metadata previews stop at 64 bytes;
use CLI JSON for complete raw values. Artwork must be a PNG no larger than
4 MiB with dimensions up to 2048 × 2048. Unreadable artwork falls back to a
package icon; unknown metadata is labeled explicitly. Inspection and extraction
run on background workers.

Install GTK **4.10+**, libadwaita **1.5+** development packages, `pkg-config`,
and `blueprint-compiler`, then run:

```sh
cargo run --release -p pkg-gtk
cargo run --release -p pkg-gtk -- /path/to/game.pkg
```

Use **Open** (Ctrl+O) or drop a single package anywhere in the window to inspect it.
Drops are ignored while an operation is active. **Extract** asks for a parent folder
and creates `<package-stem>-extracted` inside it. That directory must not already
exist. Errors include the partial output path when extraction fails. Extraction
uses a modal dialog with byte-based progress, written/total MB, live output MB/s
and Cancel. Package preparation shows an indeterminate bar until the decoded
output size is known. Progress counts extracted bytes, not compressed input;
MB uses decimal units. The window stays open until the operation finishes.
**Cancel** stops extraction between 64 KiB chunks or entries. During initial
package-tree preparation, cancellation takes effect once preparation finishes.
Cancelled partial output remains marked `.pkg-tools-incomplete`; the dialog
names its location. Remove that output folder before retrying, or choose a
different parent. The library's format and extraction limits below also apply
to the GUI. Use release builds for extraction: debug crypto/decompression is
substantially slower.

**Convert to ZAR…** in the hamburger menu converts the loaded base game, optionally with a matching
update selected in the dialog. Choose a new lowercase `.zar` filename; the update
is saved beside it as `<name>-UPDATE.zar`. Conversion uses the same validation as
the CLI and streams on a background worker with decoded-byte progress and Cancel.
Cancellation removes unpublished scratch archives. Preparation and final
publication are not interruptible; if update publication fails after the base
is complete, the error identifies the saved base archive.
Conversion is PS4-only; the action is disabled for PS3 packages.

Blueprint is compiled and embedded during the Cargo build; no external UI files
are needed at runtime. Plain `cargo build` retains the library/CLI-only build;
`--workspace` includes the GUI and requires its system dependencies.

Optional desktop launcher installation (ensure `~/.local/bin` is on `PATH`):

```sh
cargo build --release -p pkg-gtk
install -Dm755 target/release/pkg-gtk ~/.local/bin/pkg-gtk
install -Dm644 crates/pkg-gtk/data/io.github.pkg_tools.PkgTools.desktop \
  ~/.local/share/applications/io.github.pkg_tools.PkgTools.desktop
```

## AppImage release

On Linux, with the GUI build dependencies above, `curl`, and the Adwaita icon
theme installed:

```sh
bash scripts/build-appimage.sh
./target/appimage/PKG_Tools-0.1.0-x86_64.AppImage
```

The script builds the locked release version, bundles GTK/libadwaita and their
resources using linuxdeploy, and writes an AppImage plus a SHA-256
checksum to `target/appimage/`. Packaging tools are downloaded on first use and
cached in `target/appimage-tools/`; remove that directory to refresh them.
The architecture follows the build machine. Without FUSE, launch with
`--appimage-extract-and-run`.

Build on the oldest Linux distribution you intend to support: AppImage does not
bundle glibc, and builds on rolling-release systems can require a newer host
glibc. Cross-distribution compatibility must be checked separately.

## Libraries

- `ps3_pkg::Package::open(reader)` exposes `header()`, raw `metadata()`, sorted
  `entries()`, `read_param_sfo()`, `read_icon0()`, and streaming `read_entry(index)`.
  `extract`, `extract_with_cancel` and `extract_with_progress` write a new tree.
  See [PS3 contracts and limits](docs/ps3.md).
- `zarchive::Writer::create(output)` accepts `add_directory(path)` and
  `add_file(path, size, reader)` calls, parents first; `finish()` publishes.
  `zarchive::pack_directory(source, output)` packs a stable directory tree.
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
  `game.extract_with_cancel(output_dir, || cancelled)` supports cooperative
  cancellation with the same no-overwrite and incomplete-output rules.
  `game.extract_with_progress(output_dir, || cancelled, |written, total| ...)`
  reports `(0, total)` initially and decoded bytes after each output chunk.
  A successful return, rather than the byte count, confirms completion.
- `package.read_icon0()` reads plaintext artwork up to 4 MiB without opening PFS;
  missing artwork returns `None`, while encrypted artwork returns an error.

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

The format-specific details below describe PS4; [PS3 validation and limits](docs/ps3.md)
are documented separately. Both share the no-overwrite filesystem rules.

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

The GUI also has an opt-in smoke test requiring a graphical session and a real
PS3 or PS4 game package. It checks package loading, drag-and-drop, artwork, dialogs and
progress/cancellation controls:

```sh
PKG_TOOLS_TEST_PACKAGE=/absolute/path/to/game.pkg \
  cargo test -p pkg-gtk blueprint_window_and_package_loading -- --ignored
```

The graphical smoke test is ignored unless explicitly requested.
Coverage includes parsing, bounded artwork,
GUI metadata helpers, key recovery, crypto known answers, nested
PFS/PFSC, direct/single/double-indirect reads, >4 GiB virtual files/offsets,
corruption, path collisions, symlinks, overwrite refusal, cancellation, extraction
progress and incomplete output.
Both local PS4 base/full-update fixtures match reference paths, sizes and SHA-256:
4,583 files and 1,483 directories total. Header/SFO comparisons also pass. Reproduction:
[reference comparison](tests/reference/README.md).

PS4 DLC, PS4 retail extraction, delta patches,
64-bit PFS inodes and per-file PFS compression are unsupported. No emulator or
Windows/macOS compatibility claim follows from extraction results.

See [plan](PLAN.md), [compatibility targets](docs/compatibility.md), and
[dependency/fixture notes](docs/dependencies-and-fixtures.md).
