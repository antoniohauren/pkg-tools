# Explore selection contract

This is the step 1 acceptance specification for Explore. Listing, extraction
and GTK selection coverage is executable.

## Rules

- Selection refers to entries in the currently opened package's application
  tree: PS3 package entries or the PS4 application tree, not its outer container.
- Selecting a file includes only that file. Selecting a folder includes the
  folder and every descendant, including empty folders and zero-byte files.
- The result is the union of the selected entries and subtrees. Repeated or
  overlapping selections include each entry once, regardless of selection order.
- Keep paths relative to the application root. Do not flatten paths or add a
  package-name folder inside the extraction destination.
- Include every parent folder needed to reach an included entry. Including a
  parent this way does not include its other children.
- Match whole path components: selecting `data` does not select `database`.
- Extract Selected is enabled only when at least one entry is selected, subject
  to the existing operation/loading guards. A selected empty folder or zero-byte
  file counts as a selection; selected byte count is not the enablement condition.
- Clearing selection disables Extract Selected. An empty selection never means
  Extract All and must not start extraction or create output.
- Selection does not modify the package. Existing path validation and safe
  destination rules still apply; selection is not a way to bypass them.

## Shared fixture tree

Create synthetic supported PS3 and PS4 packages with this same application tree.
The listed byte strings are file contents; `/` suffixes mark folders. The root
is not a selectable entry. Exercise PS3 both with explicit parent directory
entries and with parents implied by file paths where the format permits it.

```text
README.txt                  "readme" (6 bytes)
data/
  one.bin                   "one" (3 bytes)
  nested/
    two.bin                 "two!" (4 bytes)
    zero.bin                "" (0 bytes)
    empty/
  unused.bin                "unused" (6 bytes)
database/
  other.bin                 "other" (5 bytes)
empty/
```

## Acceptance cases

Run **every row twice**, once against each format. Use test IDs
`ps3_selection_<case>` and `ps4_selection_<case>` so neither format's coverage
can be mistaken for the other's. Each case starts with no selection and a fresh
destination. Paths below are relative to that destination.

| Case | Selected paths | Exact output files | Exact output folders | Extract Selected enabled |
| --- | --- | --- | --- | --- |
| `none` | none | none | none | no |
| `file` | `data/nested/two.bin` | `data/nested/two.bin` | `data/`, `data/nested/` | yes |
| `files` | `README.txt`, `data/one.bin` | `README.txt`, `data/one.bin` | `data/` | yes |
| `folder` | `data/nested/` | `data/nested/two.bin`, `data/nested/zero.bin` | `data/`, `data/nested/`, `data/nested/empty/` | yes |
| `subtree` | `data/` | `data/one.bin`, `data/nested/two.bin`, `data/nested/zero.bin`, `data/unused.bin` | `data/`, `data/nested/`, `data/nested/empty/` | yes |
| `overlap` | `data/`, `data/nested/`, `data/nested/two.bin` | same as `subtree` | same as `subtree` | yes |
| `duplicate` | `data/one.bin`, `data/one.bin` | `data/one.bin` | `data/` | yes |
| `empty_folder` | `empty/` | none | `empty/` | yes |
| `nested_empty_folder` | `data/nested/empty/` | none | `data/`, `data/nested/`, `data/nested/empty/` | yes |
| `zero_byte_file` | `data/nested/zero.bin` | `data/nested/zero.bin` | `data/`, `data/nested/` | yes |
| `mixed` | `README.txt`, `data/nested/`, `empty/` | `README.txt`, `data/nested/two.bin`, `data/nested/zero.bin` | `data/`, `data/nested/`, `data/nested/empty/`, `empty/` | yes |
| `clear` | select `data/`, then clear selection | none | none | no |

For each format:

- Listing/selection tests assert the exact resolved set, including required
  parents. Duplicate selections may be supplied at the selection boundary even
  if GTK's selection model cannot produce duplicates.
- Extraction tests assert the exact output tree and original file contents,
  not just the presence of selected files. Ignore only the destination root
  itself when comparing folder sets. For `none` and `clear`, assert no operation
  starts and the destination does not exist.
- In `subtree` and `overlap`, explicitly assert `database/other.bin` is absent.
- In `overlap` and `duplicate`, assert each resolved entry is processed once;
  output presence alone cannot detect repeated writes. Repeat with selection
  order reversed and require the same result.
- Compare source package bytes before and after selection/extraction; they must
  be unchanged.
- GTK tests check button sensitivity for `none`, `file`, `empty_folder`,
  `zero_byte_file` and `clear`, using the corresponding loaded package tree.

Extraction cases are covered by `crates/pkg-ops/tests/selection.rs` for both
formats, including explicit/implied PS3 parents. PS4 adds container metadata under
`sce_sys`. Paths supplied to extraction APIs omit the display-only trailing `/`.
The `none` and `clear` backend cases both supply an empty selection; GTK state
changes and button sensitivity are covered by the display-required
`explore_tree_selection_and_package_changes` GTK smoke test. That test also
exercises both extraction actions through the destination picker for all three
selection fixtures. Safety and progress checks cover cancellation, markers,
unsafe selections, overwrite refusal and selected-extraction read failures.
