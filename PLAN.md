# PKG Tools implementation plan

## Goal

Build a library-first Rust toolkit for inspecting and extracting PlayStation packages, and converting PS4 fake packages (FPKGs) into ZArchive (`.zar`) files usable by shadPS4.

Target Linux first, with portable implementations and subsequent Windows/macOS verification. Minimize external code without reimplementing cryptographic or compression primitives.

## Agreed scope

- PS4: inspect and extract FPKGs; convert supported FPKGs to ZAR.
- PS3: inspect and extract PKGs. Establish the supported package variants during format investigation.
- Independently usable Rust libraries, joined by a command-line frontend.
- Native Rust implementations of package formats and the ZAR writer.
- Bounded-memory processing suitable for large games.
- No dependency on the original Windows tools or a C++ ZArchive wrapper.

Outside the MVP: PS4 retail package extraction, PKG creation, GP4 projects, SFO editing, trophy authoring, PSX/PS2-FPKG builder integration, executable patching/backporting, and PS3-to-ZAR conversion. The native GNOME GUI was originally outside the MVP and has since been implemented.

Package extraction and executable decryption are distinct operations. ZAR conversion preserves supported input contents; it does not guarantee that arbitrary executables will run in shadPS4.

## Post-MVP backlog

These are future candidates, not requirements for completing the current MVP.
Package-authoring work should start with PKG creation and GP4 support, followed
by SFO editing. Each feature needs its own format investigation and reference
compatibility checks before support is claimed.

- **PKG creation and repacking:** build PS4 FPKGs from application directories;
  rebuild extracted base games and full updates.
- **GP4 projects:** generate, read, and write base/update projects, including
  selecting the base application PKG when building an update.
- **Build compatibility:** preserve required base-game keystones across rebuilds
  and failures, prevent accidental inclusion in updates, validate packages over
  100 GB, and investigate minimum-firmware metadata behavior against CyB1K's
  patched tools. Metadata changes alone do not backport executables.
- **PARAM.SFO editing:** edit and serialize metadata with validation, preserving
  unknown fields where possible.
- **Trophy authoring:** create/edit trophy resources and build TRP files.
- **PSX/PS2-FPKG integration:** support package-building workflows used by
  PSX-FPKG and PS2-FPKG tools; this does not imply implementing emulation.
- **PS4 retail extraction:** investigate required decryption material and define
  supported inputs separately from fake-package extraction.
- **Executable decryption/patching/backporting:** scope separately from container
  extraction and metadata editing.
- **PS3-to-ZAR conversion:** establish a concrete consumer and archive layout
  before implementation; current shadPS4 conversion targets PS4 only.

Comparison reference: [CyB1K's PS4 Fake PKG Tools 3.87](https://github.com/CyB1K/PS4-Fake-PKG-Tools-3.87).
Its repository listing and README establish workflow targets, not verified
option-level parity; the Windows binaries have not been run for this comparison.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `psf` | Read PARAM.SFO metadata shared by PS3 and PS4, preserving typed and unknown fields. |
| `ps4-pkg` | Inspect FPKGs, enumerate files, expose file contents, and extract them. Keep PFS implementation internal initially. |
| `ps3-pkg` | Inspect, enumerate, and extract supported PS3 package variants. |
| `zarchive` | Write shadPS4-compatible ZArchive files from streamed file contents. |
| `pkg-cli` | Detect inputs, present metadata, extract files, and coordinate PS4-to-ZAR conversion. |

Use a Cargo workspace. Avoid a generic platform abstraction or shared utility crate until actual reuse warrants one.

Library interfaces should stay small: open a package, inspect metadata, enumerate entries, and read entry contents. Use standard Rust I/O traits where practical; package readers may require seekable input. Keep console output and progress presentation in the CLI.

## Dependency policy

- Implement binary parsing, validation, format layouts, and conversion logic in this workspace.
- Use the standard library before adding a dependency.
- Use established implementations for required cryptography, hashing, and Zstandard compression rather than writing new primitives.
- Prefer pure Rust dependencies when format compatibility and practical performance permit. Native dependencies require an explicit decision, not an implicit fallback.
- Inspect licenses, maintenance, enabled features, and transitive dependencies before selection.
- Consult upstream tools as references and use them for interoperability testing; do not vendor their implementations by default.

## Milestones

### 1. Establish compatibility targets

- Identify reliable format documentation and inspect reference implementations for PSF, PS4 PKG/PFS, PS3 PKG, and ZArchive.
- Pin reference revisions and a shadPS4 version for compatibility testing.
- Document PS4 FPKG identification, required key derivation, package encryption, PFS traversal, and extraction layout.
- Determine the exact shadPS4 archive root layout and how base games, updates, and DLC are discovered. Record supported combinations explicitly before implementing conversion.
- Identify PS3 variants and their extraction requirements; select a concrete MVP support matrix.
- Select minimal cryptographic and compression dependencies after reviewing the actual format requirements.
- Obtain representative local fixtures and expected metadata/file hashes. Keep game contents out of the repository; commit synthetic or redistributable fixtures only.

**Exit:** a concrete compatibility matrix, dependency shortlist, reference revisions, and a fixture strategy. Do not claim support for an untested variant.

### 2. Workspace, SFO, and inspection

- Create the workspace and initial crate interfaces as their functionality is implemented.
- Implement checked binary reads, offsets, lengths, and format/version validation.
- Implement SFO parsing and PS4 FPKG header/metadata inspection.
- Distinguish malformed data, unsupported variants, unavailable decryption material, and I/O failures.
- Add CLI inspection with human-readable and JSON output.

**Exit:** known-good metadata matches reference results; truncated inputs and invalid ranges fail predictably without panics or excessive allocation.

### 3. PS4 extraction

- Implement required FPKG decryption and PFS reading for the selected variants.
- Expose streaming entry reads and directory enumeration.
- Produce the expected game directory layout, including metadata placement.
- Reject unsafe output paths, symlink escapes, and ambiguous path collisions. Account for case-insensitive destination filesystems.
- Refuse accidental overwrites and surface incomplete extraction on errors.
- Keep memory use independent of total payload size; account separately for directory/index metadata.

**Exit:** extracted paths, sizes, and hashes match reference extraction for supported fixtures, including large files and corrupted input cases.

### 4. Native Rust ZArchive writer

- Implement the format's headers, file/directory tables, chunk metadata, alignment, and integrity fields according to the pinned reference implementation.
- Use Zstandard compression with the format's 64 KiB blocks.
- Confirm path encoding and case-comparison behavior; reject names or collisions that cannot be represented faithfully.
- Support streamed file input and archive finalization without buffering entire files.
- First validate archive creation from a known directory tree.
- Write to a temporary output alongside the destination and publish the final archive only after successful finalization, without silently replacing an existing destination.

**Exit:** the upstream ZArchive reader can enumerate the archive and read every file with matching hashes, including random reads across chunk boundaries, empty files, and nested directories.

### 5. Direct FPKG-to-ZAR conversion

- Connect PS4 entry readers to the ZArchive writer.
- Stream contents directly, avoiding a full extracted intermediate copy.
- Apply the verified shadPS4 layout rules rather than storing raw PKG container entries.
- Reject unsupported package combinations with actionable errors.
- Expose conversion through the CLI with useful progress and nonzero failure exit codes.
- Preserve source packages on success, failure, or interruption.

**Exit:** archive contents match reference extraction, shadPS4 recognizes the archive, and a known-compatible title loads on the pinned version. Record separately any runtime checks that require unavailable hardware or fixtures.

### 6. PS3 inspection and extraction

- Implement the selected PS3 variants using their own format and cryptographic rules.
- Reuse SFO parsing and proven common code where appropriate.
- Add PS3 detection and inspection/extraction to the CLI.
- Report unsupported variants explicitly instead of attempting PS4-style handling.

**Exit:** metadata and extracted file hashes match reference tools for each supported PS3 variant.

### 7. Portability and release checks

- Run formatting, linting, and workspace tests on Linux.
- Add Windows/macOS build and test coverage, including path handling and large offsets.
- Measure peak memory and conversion throughput on a representative large input.
- Document commands, supported variants, dependency requirements, known limitations, and reference versions.

**Exit:** Linux end-to-end checks pass; Windows/macOS status is explicitly documented and supported by available checks.

## Proposed CLI

```text
pkg-tools inspect INPUT.pkg [--json]
pkg-tools extract INPUT.pkg OUTPUT_DIR
pkg-tools convert INPUT.pkg OUTPUT.zar
```

Inspection and extraction detect PS3 versus PS4 from file contents. Conversion accepts supported PS4 FPKGs only. Final command details follow implementation needs; no additional configuration framework is planned.

## Verification strategy

- Small synthetic fixtures for parsing, bounds checking, malformed tables, and path validation.
- Reference-tool comparisons for metadata and extracted file hashes.
- Independent upstream ZArchive reader verification, rather than relying solely on our own writer/reader agreement.
- Corrupt/truncated inputs, integer overflow, short reads, destination conflicts, and interrupted/failed output checks.
- Large-file tests for offsets and bounded-memory behavior.
- shadPS4 recognition and loading checks against a pinned version.

## Open items and risks

- PS3 variant coverage, exact PS4 FPKG coverage, and base/update/DLC conversion rules require investigation.
- Minimal external code still requires vetted cryptographic and compression dependencies; the dependency shortlist is not yet verified.
- A structurally valid ZAR does not prove emulator compatibility or game playability.
- Reference implementations and documentation can differ; resolve discrepancies using pinned implementations and fixtures.
- Real interoperability checks depend on access to suitable local packages and a working shadPS4 environment.

## Current status

Milestone 3 extraction is implemented for the fixture-backed PS4 GD base/full
update subset and checked on Linux. Research and implementation notes:

- [Compatibility targets and pinned references](docs/compatibility.md).
- [Dependency shortlist and fixture strategy](docs/dependencies-and-fixtures.md).
- [Extraction contract, crypto corrections and coverage](docs/extraction.md).

The workspace contains `psf`, `ps4-pkg`, and `pkg-cli`. Inspection remains
`pkg-tools inspect INPUT [--json]`; extraction adds
`pkg-tools extract INPUT.pkg OUTPUT_DIR`. Library consumers can enumerate
application entries and borrow streaming `Read + Seek` readers. PS3 is detected
and explicitly unsupported. Safe disk extraction currently requires Unix.

Both local fixtures match reference extraction: 4,583 files, 1,483 directories,
all paths/sizes/SHA-256. Metadata inspection also matches 44 container records
and 50 SFO values. Private fingerprints/results stay under ignored `pkgs/`.
All 25 workspace tests, formatting and warning-free Clippy checks pass on Linux.
Crypto checks include fake-key recovery, DK3 digest and outer PFS header HMAC;
this does not authenticate every payload block. Synthetic tests cover malformed
inputs, path/overwrite/symlink protection, incomplete output, block indirection
and >4 GiB virtual files/offsets. See [usage](README.md) and
[reference reproduction](tests/reference/README.md).

Milestone 4 is implemented: native `zarchive::Writer`, directory-to-archive
`pkg-tools pack INPUT_DIR OUTPUT.zar`, disk-spilled chunk indexes and atomic
no-overwrite publication. Pinned upstream-reader enumeration/full-byte/random-read
checks pass, including a synthetic >4 GiB file; footer SHA-256 is independently
verified. Reader compatibility requires a 127-byte UTF-8 component limit and
rejecting wholly zero-payload archives. See [writer contract](docs/zarchive.md).

Milestone 5 direct streaming conversion is implemented in the CLI:
`convert GAME.pkg OUTPUT.zar [--update UPDATE.pkg]`. Paired inputs require matching
title/content IDs and gd/gp categories; outputs use separate base/update archives.
Both supplied fixtures pass upstream-reader full-byte/random-read comparisons
against their verified extracted trees. Recognition/loading in pinned shadPS4
remains the milestone 5 exit gate; see [conversion contract](docs/zarchive.md#pkg-conversion).
Remaining extraction coverage gates: real >4 GiB files, data DLC, additional
PFS variants, Windows/macOS verification. DLC/delta/retail extraction and per-file
PFS compression are explicitly unsupported. Emulator/runtime and base/update/DLC
conversion checks remain open. The earlier pure-Rust Zstandard frame experiment
is not ZArchive validation.
