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
cargo run --release -p pkg-cli -- trophies INPUT.pkg
cargo run --release -p pkg-cli -- trophies INPUT.pkg --json
cargo run --release -p pkg-cli -- extract INPUT.pkg OUTPUT_DIR
cargo run --release -p pkg-cli -- pack INPUT_DIR OUTPUT.zar
cargo run --release -p pkg-cli -- convert GAME.pkg Game.zar
cargo run --release -p pkg-cli -- convert GAME.pkg Game.zar --update UPDATE.pkg
cargo run --release -p pkg-cli -- liberate GAME.pkg LICENSE.rap Game-rapless.pkg
```

`inspect` and `extract` accept PS3 and PS4 packages. Inputs are detected by magic,
not filename. Rust 1.89 or newer is required;
current checks used Rust 1.99 on Linux. `psf` is standard-library-only; `ps4-pkg`
uses pure-Rust crypto/compression/XML and safe Unix filesystem calls through `rustix`.
The CLI uses `serde_json`. [Dependency decisions](docs/dependencies-and-fixtures.md).

**Experimental PS3 RAP-less conversion:** `liberate` converts supported local-license
SELF/EDAT payloads and writes a new PKG, entirely in Rust. Intended for RPCS3 and
PS3 CFW/HEN; installation/launch on both remains unverified. Supplied SSX fixture's
converted payloads and SELF signature passed independent checks.
See [supported formats and limits](docs/ps3.md#rap-less-conversion).

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

## Base GP4 projects

```sh
cargo run -p pkg-cli -- gp4 create GAME_DIR game.gp4 \
  --passcode-file /private/passcode.txt --timestamp '2026-10-31 12:00:00'
cargo run -p pkg-cli -- gp4 preflight game.gp4 --source-root GAME_DIR
cargo run -p pkg-cli -- fpkg preflight INPUT.pkg
cargo run -p pkg-cli -- gp4 image game.gp4 inner.pfsc --source-root GAME_DIR
```

Generates a narrow standalone-app GP4, **not a PKG**. Identity and versions come
from `sce_sys/param.sfo` (`CATEGORY=gd`); `eboot.bin` is required. Output must be
outside the source tree and must not exist. Passcode file must be outside that
tree: exactly 32 printable ASCII bytes, optionally followed by one LF. GP4 itself
contains the passcode; keep it private (native Unix output is mode 0600).
Timestamp is explicit UTC, not local time. Sources stay unchanged; generated
references are relative to the GP4 directory, never runtime CWD.

Library API: `ps4_pkg::gp4::Project::{from_directory, parse, preflight, to_xml,
write_new}`. Preflight explicitly approves one source root and inventories every
absolute/external reference. Updates/remaster/delta, custom PlayGo and unknown
build settings are rejected. [Exact subset and safety limits](docs/fpkg-authoring-contract.md#4-initial-gp4-subset).
Pinned synthetic GP4 load/tree/write/native-reparse checks pass; no package-build
or console compatibility follows. No GP4 GTK actions or directory/GP4-to-PKG writer.

`gp4 preflight` is a read-only authoring inventory, **not a build**. It reports
approved source references, sizes, resource roles and input/global build blockers;
exit success means inventory completed, not that a package can be built. Missing
or wrong-size keystones, NP/trophy resources, supplied PlayGo and unclassified
`sce_sys` files remain explicit blockers. Keystone size is not authentication.
Library API: `ps4_pkg::authoring::preflight(project, root, cancelled)`; cancellation
is checked before GP4 approval and between inventory entries. No payload hashing,
source snapshot, scratch, metadata edits or output publication occurs. Passcodes
and fingerprints are not printed; source paths/identity are local diagnostics.
Native PKG writing remains gated by [crypto provenance](docs/fpkg-authoring-provenance.md)
and independent integrity/crypto evidence. No `build-fpkg` command is implemented.

`fpkg preflight` inventories a supported fake GD package without changing normal
extraction. Library `authoring::preflight_package(package, cancelled)` retains the
complete original header, bounded general-digest/NP records and a supplied 96-byte
keystone; lists every container record with its authoring role; and reports unknown
records and unsupported resources as blockers. `Package::read_authoring_record`
provides capped reads, supporting only existing DK3 metadata decryption (key index
3). Other encrypted indices/algorithms fail explicitly, never use a substitute key.
CLI withholds header/digest/NP/keystone bytes and fingerprints. This is metadata
inventory, not SFO/header identity validation, full integrity checking, a stable
source snapshot or rebuild approval. Cancellation surrounds existing noninterruptible
tree preparation and is checked between entries/read chunks. No package is written.

**Native intermediate image writer:** `ps4_pkg::inner_image::InnerImage` plans and
streams clear D32 PFS images and raw-block PFSC wrappers, including lookup/hash
collisions and empty directories. `write_new` publishes only `.pfs`/`.pfsc` without
replacement; these are **not PKGs**. Callers explicitly supply validated image
entries and stable bounded payload reads, not arbitrary GP4 resources. No GP4-to-PKG
build command exists. [Image contract and executed checks](docs/fpkg-authoring-contract.md#native-clear-inner-image-writer-2026-10-31).

**GP4-to-image pipeline (Unix):** `gp4 image` now connects approved standalone-app
sources to that writer. Requires supplied original 96-byte `sce_sys/keystone`;
never generates a replacement or authenticates save identity. Preserves application
bytes and all declared directories. Places `param.sfo`, `icon0.png`, `pic0.png`,
`pic1.png` and `snd0.at9` outside the inner namespace as planned container resources;
**these resources are not emitted in the image**. Other `sce_sys` files, including
NP/trophy and supplied PlayGo, fail explicitly. No artwork/executable validation.
Library `authoring::PreparedProject::{new, resources, copy_resource, write_inner_new}`
retains checked placements and streams original resources for later container work.

Uses no-follow descriptor-relative input opens, private SHA-256/stability metadata,
bounded payload reads and full-source revalidation before no-overwrite publication.
Only `.pfs`/`.pfsc`, outside approved root; existing parents/hard links required.
Reports exact image scratch bytes before writing. Preparation and writing scan
sources multiple times; keep sources/output parents stable (not an immutable snapshot
or hostile-mutation sandbox). Cancellation is library-driven, not an interactive CLI
control. [Exact pipeline, limits and independent synthetic evidence](docs/fpkg-authoring-contract.md#native-gp4-source-to-inner-image-pipeline-2026-10-31).

**Signed/encrypted outer image (library only):** `outer_image::OuterImage` wraps
an `InnerImage` in signed S32 PFS with raw PFSC, plaintext block HMACs and AES-XTS.
`authoring::PreparedProject::write_outer_new(path, image_key, cancelled)` connects
the same approved/stability-checked GP4 sources. Requires explicit ready 32-byte
image key (`outer_image::legacy_image_key(content_id, passcode)` derives one);
only `.pfs`, never `.pkg`. No new fixed crypto keys or production dependencies.
Single/double-indirect synthetic images pass external LibOrbisPkg and Python/OpenSSL
all-reference integrity/payload checks. Container resources remain excluded;
licensing/complete container emission and full crypto provenance remain blocked.
[Contract and vectors](docs/fpkg-authoring-contract.md#native-signedencrypted-outer-image-2026-10-31).

**Base-container helpers (library only):** `container::BaseContainerLayout::plan`
reserves required base records, computes aligned offsets and the package-relative
PlayGo SHA table, and exposes final entry-table bytes and integrity ranges.
`playgo_dat` generates the default 416-byte record; `DEFAULT_PLAYGO_MANIFEST`
supplies the one-scenario XML. Streamed `write_playgo_sha` returns stored-PFS hashes;
`entry_digests`, `body_digests`, `general_digests`, `header_digest` and
`signature_digest` cover the supported keyless finalization inputs.
`encrypt_metadata` adds bounded legacy CBC for final-record-bound IMAGE_KEY,
license.dat (D[3]) and license.info (D[2]); `public_rsa_wrap` implements deterministic
public RSA-2048 wrapping with explicit raw public inputs, not authentic signing.
Synthetic padding/CBC/wrapping bytes match independent Python and pinned reference.
No SFO/PUBTOOL edits, fixed authoring keys, license generation or PKG writer. Inputs must be final,
stable scratch bytes; partial SHA output must be discarded on failure.
Synthetic pinned-reference comparisons and independent Python checks are in the
[reference checks](tests/reference/README.md). Crypto provenance, license generation
and complete finalization remain blocked; no `build-fpkg` command exists.

## Source-backed PS4 base rebuild (experimental, Unix)

```sh
cargo run --release -p pkg-cli -- fpkg rebuild INPUT.pkg NEW_OUTPUT.pkg
# Optional known passcode instead of the verified ASCII-zero candidate:
cargo run --release -p pkg-cli -- fpkg rebuild INPUT.pkg NEW_OUTPUT.pkg --passcode-file /private/passcode.txt
```

Library: `ps4_pkg::rebuild::rebuild_new(source, destination, passcode, cancelled)`;
shared frontend operation: `pkg_ops::rebuild_ps4`. Sources and existing outputs
remain untouched. One destination-sized scratch file, bounded 64-KiB payload I/O,
multiple full-source validation scans, no-overwrite hard-link publication. Keep
source/output parents stable; this is not a hostile concurrent-mutation sandbox.

Accepts narrowly checked legacy and 2019 newcrypt GD base sources with default
single-chunk PlayGo. Newcrypt ready source keys are verified against passcode and
seed; destination uses fresh legacy D[1]/zero-seed images, never copied source
flags. Preserves original SFO, ENTRY_KEYS, licenses, keystone, every application
file, paired NP records, trophy00 and supported pronunciation/save/artwork/changeinfo
resources. Encrypted NP binding storage includes its validated zero padding.
Sources must use the verified canonical general-digest recipe; modern System/
PlayGo/Trophy slots and alternate MajorParam/Content recipes remain unsupported.
Unknown container records, other trophy variants, custom PlayGo and updates fail
explicitly. Reopens and compares every retained application/resource byte before
publication. No new licenses, NP identity, keystones or authentic signatures.

Synthetic independent reader/digest/all-block-HMAC checks are documented in
[reference checks](tests/reference/README.md). **No console installation, launch,
save, NP-service or trophy compatibility claim.** No transfer/install is performed.

## GNOME application

**Trophies** lists trophy sets directly from loaded PS3/PS4 packages, with icons,
names, descriptions, grades, hidden flags and group IDs. Reading runs in the
background without an extracted temporary tree. English definitions are preferred,
then default/first available language. Hidden trophy text is shown (spoilers).
These are definitions, not earned status; no profile or console data is read.
CLI `trophies` provides the same lists as text or JSON (icons omitted from JSON).
Unreadable sets report an error without hiding other sets; CLI returns failure if
any set is unreadable. Missing trophy archives produce an empty list.

PS4 uses the existing supported FPKG application reader, not retail decryption.
Release ESFM text is decrypted with IDs from `sce_sys/npbind.dat` when available;
otherwise IDs `NPWR00000_00` through `NPWR99999_00` are tried against one encrypted
XML block. Other suffixes require a matching binding. Unsupported encryption and
malformed resources are reported explicitly. TRP archives are limited to 64 MiB
each, 128 MiB combined; XML/icons to 4 MiB each, and 4096 trophies per set.
Local verification: SSX PS3 (37 trophies), TMNT PS4 base/update (31 each).

`pkg-gtk` provides a native Rust GTK4/libadwaita interface for PS3 and PS4, authored in
Blueprint. Overview shows game artwork, title, title ID, application version,
game/patch type, package size, content ID and source. A collapsible task sidebar groups
the summary, transfer, **Explore**, conversion and **All Info** views. All Info contains headers,
SFO metadata and container records. Binary metadata previews stop at 64 bytes;
use CLI JSON for complete raw values. Artwork must be a PNG no larger than
4 MiB with dimensions up to 2048 × 2048. Unreadable artwork falls back to a
package icon; unknown metadata is labeled explicitly. Inspection and extraction
run on background workers, as does Explore listing preparation.

Main menu **Use PS4 pic1.png** switches the summary to wide PS4 artwork,
falling back to `icon0.png` when missing or unreadable. The preference is saved
in `~/.config/pkg-tools/preferences.ini` (or `$XDG_CONFIG_HOME/pkg-tools/preferences.ini`).
Images retain their original proportions; PS3 artwork and PS4 transfer icons are unchanged.

Install GTK **4.10+**, libadwaita **1.5+** development packages, `pkg-config`,
and `blueprint-compiler`, then run:

```sh
cargo run --release -p pkg-gtk
cargo run --release -p pkg-gtk -- /path/to/game.pkg
```

Use **Open Package…** in the main menu (Ctrl+O) or drop a single package anywhere
in the window to inspect it. The full-height sidebar has its own header;
the sidebar button in the content header hides or restores it.
For a loaded PS4 package, **Send to PS4** serves the local file over HTTP and
sends the DirectPackageInstaller payload to GoldHEN BinLoader. Enable GoldHEN's
BinLoader Server, enter the console's LAN IPv4 address, and keep the computer
awake until transfer completes. HTTP byte ranges are supported; remote URLs and
proxy downloads are not.
**Send to PS4** is available from startup, without opening a package first.
**Send Multiple Packages…** selects local PS4 packages and sends them sequentially
in file-picker order using one installer payload. All selected packages are checked
before sending starts. Progress shows the current package and its transferred bytes.
Cancel or an error stops the batch; already transferred packages remain on the PS4.
Transfer completion does not confirm installation success; check the console.
Drops are ignored while an operation is active. **Explore** browses an expandable,
multi-select application file tree with decoded file sizes, without extracting a
temporary tree. Use the keyboard or Ctrl/Shift-click to select files and folders.
**Extract All…** extracts the complete application; **Extract Selected…** extracts
selected files and folder subtrees, preserving package-relative paths, required
parents and empty selected folders. Overlapping selections write each entry once;
the selected action is disabled when nothing is selected. Listings and selections
persist across page changes and reset when another package is loaded.
Both actions ask for a parent folder and create `<package-stem>-extracted` inside
it. Generated extraction and liberation
folder names are capped at 31 UTF-8 bytes (preserving the suffix) to avoid RPCS3's
HDD-game directory-name assertion. That directory must not already
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

Explore uses virtualized rows and creates child models on expansion, but tree
metadata still consumes memory proportional to entry/path count within the format
limits below. Unsupported package trees show a browse error; header inspection
alone does not guarantee browsing support. No search, previews or selective CLI
command is provided. Keep source packages unchanged while browsing/extracting;
selection identity checks detect application reloads, not external file replacement.
See [listing and selection API](docs/extraction.md#explore-and-selective-extraction-ps3-and-ps4).

**Convert to ZAR…** in the Convert view converts the loaded base game, optionally with a matching
update selected in the dialog. Choose a new lowercase `.zar` filename; the update
is saved beside it as `<name>-UPDATE.zar`. Conversion uses the same validation as
the CLI and streams on a background worker with decoded-byte progress and Cancel.
Cancellation removes unpublished scratch archives. Preparation and final
publication are not interruptible; if update publication fails after the base
is complete, the error identifies the saved base archive.
Conversion is PS4-only; the action is disabled for PS3 packages.

For PS3, choose **Liberate…** from the Convert view, then choose a PKG, the loaded
package, or an extracted game folder (containing `PARAM.SFO` and `USRDIR`).
The dialog finds `<content-id>.rap` beside the source or in nearby `exdata` folders
(also inside extracted folders), ignoring filename case. You can **Link RAP…**
manually instead; multiple matches require manual selection. The separate overview
link still applies only to the loaded package and clears when another is opened.
Choose **Folder…** or **PKG…** as output. Folder output writes liberated files
directly into a new `<source>-liberated` folder inside the selected parent;
PKG output repacks them into a new `.pkg`. Both accept PKG or folder inputs.
Conversion validates the license against encrypted payloads and runs in a background
worker with Cancel, without replacing existing files. Interrupted folder output is
marked incomplete; remove that output folder before retrying.
Use a release build, especially for developer-key discovery and repacking.

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

- `ps4_send::send_batch` transfers inspected local PS4 packages through GoldHEN
  BinLoader with sequential batches, HTTP byte ranges, cancellation and progress.
  Callers supply matching package metadata; completion does not confirm installation.
  Its bundled payload and license live in `crates/ps4-send/data/dpi-payload`.
- `pkg_ops` owns shared PS3/PS4 listing and extraction dispatch, PS3 liberation input handling
  and PS4-to-ZAR conversion. CLI and GTK depend on it directly; presentation and
  command-line reporting remain in their respective frontends.
  Use `pkg_ops::list` for read-only application paths, kinds and decoded sizes;
  `pkg_ops::extract_selected` extracts exact paths and their subtrees.
  Use `pkg_ops::extract`, `pkg_ops::liberate::liberate` and
  `pkg_ops::convert::run_with_progress` for cancellable operations with byte progress.
- `ps3_pkg::Package::open(reader)` exposes `header()`, raw `metadata()`, sorted
  `entries()`, `read_param_sfo()`, `read_icon0()`, and streaming `read_entry(index)`.
  `extract`, `extract_with_cancel` and `extract_with_progress` write a new tree;
  `extract_selected_with_progress` writes selected paths and subtrees.
  See [PS3 contracts and limits](docs/ps3.md).
- `zarchive::Writer::create(output)` accepts `add_directory(path)` and
  `add_file(path, size, reader)` calls, parents first; `finish()` publishes.
  `zarchive::pack_directory(source, output)` packs a stable directory tree.
- `psf::parse(&bytes)` reads SFO 1.0/1.1, retaining typed values, unknown formats,
  original bytes and capacity padding. Keys and text remain byte slices;
  callers choose whether to decode UTF-8. Integers preserve all 32 bits.
  `psf::serialize(&sfo)` emits checked SFO 1.1, preserving entry order, raw values,
  formats, capacities and padding. Typed values must agree with raw bytes; original
  offsets, layout gaps and trailing bytes are not preserved. No metadata is edited
  automatically. Serialization uses the same resource limits as parsing.
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
  `game.extract_selected_with_progress(output_dir, &["path"], || cancelled,
  |written, total| ...)` applies the same rules to selected paths and subtrees.
- `package.read_icon0()` and `package.read_pic1()` read plaintext artwork up to 4 MiB without opening PFS;
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

The graphical smoke test is ignored unless explicitly requested. A separate
[Explore smoke test](tests/fixtures/README.md#explore-graphical-smoke-test) uses
synthetic PS3/PS4 fixtures and checks browsing, selection, both extraction buttons,
the in-process destination picker, cancellation and stale-selection rejection.
See [Explore validation](docs/explore-plan.md#7-document-and-validate) for executed
checks and remaining manual limits.
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
