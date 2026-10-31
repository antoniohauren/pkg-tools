# PKG Tools

> Library-first Rust toolkit for PlayStation packages on Linux, with a CLI and a native GNOME GTK4/libadwaita frontend.

Instructions for AI coding agents working in this repository.

## Setup

- Build libraries and CLI: `cargo build`
- Build including GUI: `cargo build --workspace`
- Run tests: `cargo test --workspace`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Check formatting: `cargo fmt --all --check`
- Rust 1.89+ is required. GUI builds also require GTK 4.10+, libadwaita 1.5+, `pkg-config` and `blueprint-compiler`; see `README.md` for setup and opt-in graphical tests.

## Code style

- Keep code human-readable; use named constants instead of magic numbers.
- Run `cargo fmt --all`; Clippy must pass with no warnings.
- Prefer `Result` over panics in library code.
- No `unwrap()` in non-test code without a justifying comment.
- Keep format parsing and operations in libraries; CLI and GTK own presentation.

## Project structure

- `crates/psf`: PARAM.SFO parsing.
- `crates/ps3-pkg`, `crates/ps4-pkg`: package inspection and streaming application reads.
- `crates/pkg-fs`: shared filename and safe extraction rules.
- `crates/zarchive`: native streaming ZArchive writer.
- `crates/ps4-send`: GoldHEN package transfer.
- `crates/pkg-ops`: shared operations used by both frontends.
- `crates/pkg-cli`, `crates/pkg-gtk`: CLI and Blueprint-based GNOME application.
- `tests/`: fixture and independent reference-check instructions; private package data stays under ignored `pkgs/`.
- Read `README.md` for current capabilities and commands. For format changes, read `docs/compatibility.md` and the relevant PS3, extraction or ZArchive contract. For authoring work, read `docs/fpkg-authoring.md`; planned features are not implemented capabilities.

## Guardrails

- Let Cargo update `Cargo.lock`; never edit it by hand.
- Keep Rust code safe: workspace lints forbid `unsafe`.
- Run formatting, workspace Clippy and workspace tests before marking code changes complete. Report unavailable system dependencies, skipped graphical/reference checks and failures explicitly.
- Check existing dependencies and `docs/dependencies-and-fixtures.md` before adding one. Implement simple functionality directly; use established crypto/compression primitives rather than writing new ones.
- Preserve source packages and existing outputs. Keep no-overwrite publication, path/symlink validation, cancellation and incomplete-output handling intact.
- Stream payloads with bounded buffers; validate untrusted lengths, offsets and paths before allocation or I/O.
- Keep game contents, RAPs, secret material and private fixture fingerprints out of commits and logs. Commit only synthetic or redistributable fixtures.
- Match existing patterns and keep changes scoped. Ask before large refactors or public API renames.
- Separate synthetic tests, independent reference comparisons and actual console/emulator checks. Claim support only for verified variants; document remaining compatibility gates.

## Commits & pull requests

- Use Conventional Commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`.
- Keep PRs focused on a single concern; describe what changed and why.
