# Explore feature implementation plan

Replace the GTK application's Extract page with Explore: browse package files
without extracting them, then extract everything or selected files and folders.
Support the existing PS3 and PS4 package formats; keep source packages read-only.

## 1. Define selection rules

- Files select individually; selecting a folder includes all descendants.
- Overlapping selections extract each entry once.
- Preserve package-relative paths, required parent folders and empty selected folders.
- Disable **Extract Selected…** when nothing is selected.

Done when these rules have explicit test cases covering both package formats.

Selection contract and per-format acceptance cases:
[Explore selection contract](explore-selection.md). These define expected
behavior; executable coverage follows as steps 2–5 add the required APIs and UI.

## 2. Add shared package listing

- Expose entry paths, kinds and sizes through `crates/pkg-ops`.
- Reuse PS3 package entries and the PS4 application tree.
- Read and decode directory metadata without writing a temporary extracted tree.
- Preserve existing format validation and resource limits.

Done when supported PS3/PS4 packages return application file listings without
creating output files, and unsupported inputs report clear errors.

## 3. Support selective extraction

- Add selection support to the existing extraction paths in `crates/ps3-pkg`
  and `crates/ps4-pkg`, dispatched through `crates/pkg-ops`.
- Include required parent directories and deduplicate overlapping selections.
- Calculate progress from selected files' decoded sizes.
- Preserve existing full-extraction APIs, cancellation, no-overwrite protections,
  path validation and incomplete-output markers.

Done when selected extraction writes exactly the requested subtree plus required
parents, while full extraction retains its existing behavior.

Implemented: both format readers expose `extract_selected_with_progress`,
dispatched by `pkg_ops::extract_selected`. Exact application paths resolve to a
deduplicated subtree plus required parents; empty/unknown selections fail before
output. Acceptance and safety coverage lives in `crates/pkg-ops/tests/selection.rs`,
with format-level chunk-cancellation checks. GTK selection wiring remains steps 4–5.

## 4. Replace the Extract page with Explore

- Update `crates/pkg-gtk/data/window.blp` and GTK navigation wiring.
- Show an expandable, multi-select file tree with names and file sizes.
- Use a virtualized GTK list/tree model for large packages.
- Add **Extract All…** and **Extract Selected…** actions.
- Provide loading, empty and unsupported/error states.

Done when users can browse nested folders, select files/folders with keyboard or
pointer, and invoke either extraction action.

Implemented: Explore replaces Extract in GTK navigation. A `GtkTreeListModel`,
`GtkMultiSelection` and virtualized `GtkListView` provide expandable folders,
file sizes and standard keyboard/pointer selection. Extract All and Extract
Selected use the existing destination and operation lifecycle; empty selections
cannot start extraction. Loading, empty and browse-error states are included.
The minimum step-5 wiring needed for working actions also loads listings on a
background worker, retains them per package and discards stale worker results.
Headless tree-index tests cover both formats; the display-required
`explore_tree_selection_and_package_changes` test covers expansion, selection,
button guards, cache retention, package changes and browse errors. Real-package,
large-tree and end-to-end destination-picker checks remain for steps 5–7.

## 5. Connect background workflows

- Load the listing when Explore first opens and retain it until the package changes.
- Clear stale listing and selection when opening another package.
- Keep listing and extraction work off the UI thread.
- Reuse the destination picker, generated output-folder naming, progress dialog,
  Cancel behavior and result dialogs.
- Ensure extraction selections refer to the package being extracted; reject stale
  selections rather than silently extracting different entries.

Done when browsing remains responsive and both actions use the existing safe
destination and operation lifecycle.

Implemented: listing reads and tree indexing run on a background worker; GTK
models are created on the UI thread. Listings and selections persist across page
changes and reset after a successful package change. Late listing results are
discarded using package generation and source path. Selected extraction snapshots
paths before opening the destination picker and validates listing identity both
before the picker and after it returns, including same-path package reloads.
Both extraction actions reuse output-folder naming, background extraction,
progress, cancellation and result dialogs. GTK regression coverage checks cache
retention, package/path identity, same-path generation invalidation and selection
reset; async waits are bounded. `cargo test -p pkg-gtk` and the display-required
Explore regression pass with `GSK_RENDERER=cairo`. Real-package/large-tree
responsiveness and end-to-end destination-picker checks remain for steps 6–7.

## 6. Test behavior and safety

- Cover individual files, nested folders, overlapping selections and empty folders.
- Verify unrelated files stay excluded and selected-byte progress totals match.
- Check cancellation, incomplete-output markers, unsafe paths and overwrite refusal.
- Check package changes clear selection and listing state.
- Extend the GTK smoke test for browsing and extraction actions.

Done when automated tests pass for both formats and the graphical checks pass
where a display and supported package fixtures are available.

Implemented: shared selection tests cover exact output trees, individual and
multiple files, nested/overlapping folders, empty folders, zero-byte files,
selected-byte progress totals and unchanged source bytes for both formats
(including explicit/implied PS3 parents). Safety checks cover invalid/unsafe
selections, cancellation before output and between chunks, incomplete-output
markers, symlink escapes, and refusal to reuse completed, partial, empty, file
or symlink destinations. Format tests retain malformed/unsafe package-path
coverage and now check selected-extraction read failures leave markers too.
The display-required Explore smoke test exercises browsing, selection/button
guards, package-change resets, both real extraction button callbacks through
the destination picker and background worker, exact resulting paths, picker
cancellation, selection snapshots and stale-generation rejection after picking.

Validation: `cargo test --workspace` passed (98 tests; 5 ignored),
`cargo clippy --workspace --all-targets -- -D warnings` passed, and the Explore
graphical test passed with `GDK_DEBUG=no-portals`, `GSK_RENDERER=cairo` and
`G_DEBUG=fatal-criticals`. See `tests/fixtures/README.md` for the smoke command.
Only synthetic package fixtures were used; real-package, native portal picker
and large-tree responsiveness checks remain for step 7. The synthetic PS4
fixture bypasses metadata inspection because its container SFO is placeholder
data; listing and extraction still use the actual package readers/workers.

## 7. Document and validate

- Update README and extraction/API documentation with Explore behavior and limits.
- Run `cargo fmt --all --check`.
- Run `cargo clippy --workspace --all-targets -- -D warnings`.
- Run `cargo test --workspace`.
- Check real PS3/PS4 packages and large-tree responsiveness when fixtures and a
  graphical session are available; record any checks that could not run.

Done when validation results and remaining limitations are reported.

Completed (Linux graphical session, 2026-10-23): README and PS3/extraction API
documentation now describe Explore, exact-path selection, progress, caching,
source stability, output safety and unsupported features.

Validation:

- `cargo fmt --all --check`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo test --workspace`: passed, 99 tests passed and 6 ignored (three opt-in
  graphical tests and three fixture generators).
- `tests::explore_tree_selection_and_package_changes`: passed separately with
  `GDK_DEBUG=no-portals`, `GSK_RENDERER=cairo`, `G_DEBUG=fatal-criticals` and isolated
  `XDG_DATA_HOME`. Covers the synthetic PS3 retail/debug and PS4 workflows,
  including both extraction buttons and the in-process destination picker.
- `tests::blueprint_window_and_package_loading`: passed separately for the local
  PS3 retail SSX package and both PS4 TMNT base/full-update packages, using the
  same graphical settings. This checks package loading/metadata, not real-package
  Explore destination-picker extraction.

An ad hoc, external Rust harness called `pkg_ops::list` and
`pkg_ops::extract_selected` on those three read-only sources, then rendered the
actual `explore.rs` tree/factory with GTK in this session. Every tree expanded to
its listing count, selection resolved one path, and scrolling completed without
GTK criticals. Each package's smallest nonempty file extracted into a fresh
temporary destination with exactly one output file, expected size, matching
selected-byte progress and no incomplete marker. Temporary output was removed.

| Local fixture | Files | Directories | Decoded file bytes |
| --- | ---: | ---: | ---: |
| PS3 retail SSX | 64 | 7 | 4,172,936,152 |
| PS4 TMNT base | 2,735 | 632 | 883,526,661 |
| PS4 TMNT full update | 1,848 | 851 | 747,688,709 |

The same harness rendered a synthetic 100,100-entry tree (100 root folders, each
with 1,000 files), expanded every folder, selected a file and scrolled to the
middle/end/back. Indexing took about 38 ms on a worker; window creation,
expansion and scrolling took about 471 ms including deliberate event-loop waits.
Largest single folder expansion was about 21 ms; four requested 20 ms event-loop
waits each returned within 24 ms. Real trees' largest expansions were under 7 ms.
These are local debug-build observations, not a responsiveness guarantee. PS4
listing preparation took 12.5–13.8 seconds in this debug harness; release builds
are recommended. Initial parsing remains non-interruptible.

Remaining checks/limits: native portal destination pickers and hands-on keyboard/
pointer behavior were not manually checked. Real-package extraction through the
GUI picker, full payload rehashing and full real-package extraction were not
repeated; selective real checks verified output shape/size/progress, not content
hashes. The harness is local validation code under `/tmp/opencode`, not a committed
benchmark or new CLI. Near-limit million-entry trees, a single extremely wide
folder, real PS3 debug packages, other hardware/renderers and Windows/macOS remain
unverified. The 100,100-entry tree checks rendering/model behavior, not parsing a
real package of that size. Reproduction commands and manual follow-ups:
[fixture test instructions](../tests/fixtures/README.md#explore-graphical-smoke-test).

## Out of scope

Search, file previews, new CLI commands, new package-format support, merging into
existing output directories and overwriting files.
