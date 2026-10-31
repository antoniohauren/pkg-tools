# PS4 FPKG authoring, GP4, update remarry and merge

Status: stage 1 source investigation recorded in the
[authoring contract](fpkg-authoring-contract.md); update binding and independent
writer acceptance remain open gates. A bounded synthetic base build/read and keyless
integrity oracle is [executed](../tests/reference/README.md); full PFS authentication,
crypto distribution provenance and console checks remain open. Minimal checked SFO 1.1 serialization is implemented
as `psf::serialize(&sfo)`; narrow standalone-app GP4 generation/import/export is
implemented in `ps4_pkg::gp4` with CLI `gp4 create`. Read-only authoring readiness
inventory is implemented in `ps4_pkg::authoring::preflight` and CLI `gp4 preflight`;
it reports resource/input blockers and the still-open global writer gates. Package-source
inventory is implemented as `authoring::preflight_package` and CLI `fpkg preflight`;
bounded container metadata and original keystone retention do not establish rebuild
readiness or header/SFO semantic consistency. Pinned synthetic GP4
load/tree/write/native-reparse passes. Native clear inner-PFS/raw-PFSC image generation
is implemented in `ps4_pkg::inner_image`, with independent synthetic read/layout checks;
Unix `authoring::PreparedProject` and CLI `gp4 image` now connect approved, stability-checked
sources and narrow resource placement to that writer. These intermediate images are not PKGs.
Signed/encrypted S32 outer images are now implemented as `outer_image::OuterImage`
and library-only `PreparedProject::write_outer_new`, with explicit ready image key,
independent HMAC/XTS/legacy derivation vectors and single/double-indirect checks.
This does not supply licenses, PlayGo, RSA wrapping or container finalization;
numeric-input provenance and full-PKG/hardware gates remain unresolved.
No native PKG writer or remarry implementation. Native Rust, library-first,
Linux-first. Each stage has its own compatibility gate; readable output alone
does not establish installability, launchability or save compatibility.

## Goals and order

1. Build base FPKGs and full-update FPKGs from application directories and GP4.
2. Remarry an existing full-update FPKG to a selected base FPKG.
3. Later, merge one base plus one full update into a standalone base FPKG.

**Remarry** means rebuilding an update against the selected base's package
identity and required binding material. The output remains an update requiring
that base. It is not changing a title ID to force an unrelated update to install.

**Merge** means producing one newly built base package containing the effective
updated application. It is neither concatenating PKG bytes nor shipping two PKGs
in one wrapper. It differs from the existing separate base/update ZAR conversion.

Initial support: supported GD fake base packages (`CATEGORY=gd`) and complete,
non-delta fake updates (`CATEGORY=gp`) for the same title and content ID. Reject
retail inputs, DLC, delta reconstruction, cross-region/title conversion, update
chains requiring intermediate packages, and unexplained package variants.
Executable decryption, firmware backporting and general SFO editing UI are separate
work. Keep the existing extraction and separate-ZAR workflows unchanged.

## Existing code and intended ownership

- `ps4-pkg`: reuse checked readers and crypto; add native PKG/PFS writing here.
  Authoring must inventory metadata beyond the current extraction map, including
  NP resources, keystone and generated container records. Extracted trees are not
  automatically lossless rebuild inputs.
- `psf`: checked SFO 1.1 serialization retains unknown keys, types, raw values,
  capacities and padding, not original layout gaps/offsets/trailing bytes. Raw and
  typed values must agree. Authoring-specific metadata edits remain future work;
  serialization makes no automatic PUBTOOL changes.
- GP4: start as a module beside the authoring code; split into another crate only
  if actual consumers require it. Use an established XML parser after dependency
  review, not handwritten XML parsing.
- `pkg-ops`: coordinate directory/GP4 builds, package-to-package remarry and later
  merge. Reuse listing/streaming reads without changing extraction semantics.
- `pkg-cli`: first frontend. `pkg-gtk`: add background actions after CLI acceptance.
- `tests/reference`: independent build/read comparisons and private fixture
  instructions. Keep game data and secret material outside the repository/logs.

Implement shared build logic once. Do not introduce a general virtual filesystem
or configurable build framework. Stream payloads; use bounded buffers and disk
scratch for generated images/indexes when necessary. Document scratch-space needs
before starting a build; a no-intermediate-tree build is not a no-scratch build.

## 1. Establish the authoring contract

Findings and decisions: [stage 1 authoring contract](fpkg-authoring-contract.md).
The pinned reference can describe a minimal base writer, but does **not** establish
our GD full-update/remarry recipe. Its patch builder emits DP and never consumes
a selected base. Do not promote that behavior to supported full-update writing.
Stage 1's exit is therefore **not fully met**: investigation is checked in, but
binding and complete authoring acceptance are blockers, not inferred requirements.
The [synthetic base harness](../tests/reference/README.md) establishes structural
build/read checks only; [crypto provenance](fpkg-authoring-provenance.md) is not cleared.

Inspect the pinned LibOrbisPkg writer/GP4 implementation from
[compatibility research](compatibility.md), then pin any additional open-source
reference needed for authoring. References are format/oracle inputs, not runtime
dependencies. Review licensing and key-material provenance before reuse.

Record, with source locations and fixture evidence:

- Base versus update headers, flags, identity/version fields, entry ordering,
  alignment, chunk/install metadata and required generated records.
- Inner PFS, optional PFSC and outer signed/encrypted PFS construction, hash trees,
  digests, fake signatures, key derivation and encrypted metadata entry treatment.
- Required application metadata, its mapping into container/PFS namespaces, and
  which input artifacts must be preserved versus regenerated.
- Base/update binding: exactly which base digest, keys, passcode-derived material
  or other fields the builder needs, and whether these are recoverable from our
  supported FPKGs. Read-side image-key recovery is not proof of write-side support.
- Keystone/save identity behavior, NP/trophy metadata, and differences between
  untouched updates, remarried updates and merged base packages.
- Whether full updates encode deletions, opaque directories or other overlay
  semantics. If such semantics are absent, establish that from references rather
  than assuming every file absent from an update should disappear.

Separate confirmed requirements from hypotheses. Use local same-title base/update
fixtures with differing package binding for remarry; merely rebuilding an already
compatible pair does not demonstrate remarry.

**Exit:** a checked-in supported writer profile, metadata ownership table and
binding recipe, plus pinned independent tools that can build/read that profile.
If remarry needs unavailable material, document the required explicit input or
stop that profile; do not silently substitute zero keys or rewrite identity.

## 2. GP4 and minimal SFO writing

Support generating, reading and writing the base/full-update GP4 subset required
by the chosen writer profile:

- Project format/version, volume type, package settings, file mappings and
  directory hierarchy; update projects explicitly reference their base PKG.
- Generate projects from an application directory without changing its contents.
  Read identity/version from SFO, not directory naming conventions.
- Resolve relative source and base-package paths against the GP4 location, never
  the process working directory. Generated projects use relative paths where
  practical. External/absolute source references must be surfaced during preflight,
  not silently treated as files inside a selected root.
- Validate XML size/depth/counts, reject DTD/external entity resolution, invalid
  destination paths, duplicate mappings and case/file-directory collisions.
  Validate source files and symlinks using the same explicit source policy as
  directory builds; project destinations never become unchecked host paths.
- Define a supported GP4 schema subset. Reject unsupported build-affecting
  settings with their names; do not silently discard them and claim a faithful
  round trip. Preservation of unsupported XML is not execution support.
- SFO serializer uses checked offsets, capacities, terminators and alignment.
  Preserve unknown fields unless a documented authoring rule requires rejecting
  them. Emit a change summary for every field authoring changes.

**Exit:** generated base/update GP4s load in the pinned reference; imported supported
reference projects retain equivalent build settings/file mappings after writing.
SFO parse/write/reparse preserves untouched values, formats and capacities.

## 3. Native base FPKG writer

Build one documented profile first, using synthetic/homebrew application inputs.
Add compression or layout variants only when needed for that profile.

1. Preflight the complete input tree, SFO/header consistency, required metadata,
   supported file kinds and representable sizes/offsets before writing output.
2. Establish explicit generation rules for new homebrew keystones/binding material;
   existing game rebuilds preserve required original material. Missing required
   keystone is an error, not an invitation to invent a replacement.
3. Build application images, metadata records, crypto and integrity structures
   according to the verified contract. Regenerate container artifacts rather than
   copying stale digests/signatures from source packages.
4. Finalize into scratch beside the destination, verify the completed package,
   then publish without replacing an existing file. Reject output/source aliasing.
   Cancellation/failure removes unpublished scratch and preserves every input.
5. Report phase, progress, disk requirements and actionable errors. Count payload
   work separately from final hashing/publication; never show success prematurely.
   Revalidate input stability across multi-pass builds and fail on detected changes.

**Exit:** our reader and an independent reader agree on paths, bytes and metadata;
independent integrity checks pass; a homebrew package installs and launches on the
test PS4. Rebuild a permitted local base fixture and test its launch/save behavior
separately. Exercise >4 GiB file/offset handling; >100 GB support remains unclaimed
until verified, with format ceilings checked before expensive writing.

## 4. Full-update building and remarry

First build a full update directory/GP4 against a selected base. Then accept an
existing full-update package as the source of that same shared build pipeline.

Preflight must:

- Open both packages using supported fake-key/PFS checks, not filename/header
  guesses. Validate base/update roles, header/SFO agreement, title/content IDs,
  versions and supported patch flags. Reject downgrades and contradictory metadata
  in the initial workflow; package version compatibility needs its own documented rule.
- Read required base binding material and update application/NP/trophy resources.
  Report missing or unsupported material before building; do not pretend the
  existing extraction mapping captures everything authoring needs.
- Show source base, source update, identities, versions and intended output.
  An already-compatible pair may be rebuilt, but is not evidence of remarry.

Rebuild the update with base linkage and crypto generated by the writer. Preserve
update payload bytes, update category/version and game identity except for the
specific verified binding/authoring fields. Do not copy the base's entire
`sce_sys` into the update, put a base-only keystone into it, alter executables or
lower firmware metadata to suggest backporting.

**Exit:** independent validation accepts the update; payload hashes match the
source update except for enumerated metadata changes. On the test PS4, install
the selected base and remarried update, launch the updated game, verify its version,
trophies and save/load behavior. Record firmware/tool versions and any required
uninstall/reinstall procedure with a save-backup warning. A previously incompatible
same-title binding pair must become usable; stop short of claiming that until tested.

## 5. Later: merge base plus full update

Implement only after base writing and remarry are accepted. Accept one base and
one complete update; reuse the same compatibility preflight and writer.

- Build an effective application manifest: base entries with update replacements
  and additions. Honor verified deletion/opaque semantics. Missing update paths
  alone do not mean deletion. Reject unresolved file/directory and case collisions.
- Resolve `sce_sys` by the researched metadata ownership table, not blanket
  last-file-wins: carry updated application/version metadata, preserve required
  base keystone/save identity, and retain NP/trophy resources consistently.
- Re-author as a standalone base (`gd` plus appropriate package flags/records),
  removing patch-only linkage and regenerating container integrity. Define
  `APP_VER`/base-version handling through reference and console tests; retain the
  effective update version where the supported format permits it.
- Stream chosen files from their source packages, using scratch images as required.
  Emit a summary of replacements, additions, deletions and metadata changes.

**Exit:** independent extraction matches the expected effective application tree;
the merged PKG installs and launches without a separately installed source base or
update. Verify updated content, version, trophies and save/load on the test PS4.
Existing-save compatibility remains unclaimed until an explicit migration test.
Choose any uninstall/reinstall test only after backing up saves.

## Frontends and proposed CLI

Command names are proposals; finalize alongside implementation. Preserve existing
`pack` (directory-to-ZAR) and `convert` (separate base/update ZARs) behavior.

```sh
# Generate project, then build it; update projects require explicit base.
pkg-tools gp4 create GAME_DIR game.gp4 --passcode-file /private/passcode.txt --timestamp '2026-10-31 12:00:00'
pkg-tools gp4 preflight game.gp4 --source-root GAME_DIR # inventory only, not a build
pkg-tools fpkg preflight INPUT.pkg # package-source inventory only
pkg-tools gp4 image game.gp4 inner.pfsc --source-root GAME_DIR # intermediate only; supplied original keystone required
# Everything below remains proposed, not implemented:
pkg-tools gp4 create UPDATE_DIR update.gp4 --base GAME.pkg
pkg-tools build-fpkg game.gp4 Game.pkg
pkg-tools build-fpkg update.gp4 Update.pkg

# Direct directory build uses the same settings/validation as GP4.
pkg-tools build-fpkg GAME_DIR Game.pkg
pkg-tools build-fpkg UPDATE_DIR Update.pkg --base GAME.pkg

pkg-tools remarry GAME.pkg UPDATE.pkg Update-remarried.pkg
# Later: one standalone FPKG, not the existing paired-ZAR conversion.
pkg-tools merge GAME.pkg UPDATE.pkg Game-updated.pkg
```

Library operations expose cancellation, phase/progress and changed-metadata
summaries. GTK subsequently adds Create FPKG, GP4 import/export, Remarry Update and,
later, Merge Base + Update. Reuse current workers, busy-state, destination pickers
and no-overwrite rules. Show both input identities and output role before starting;
keep console transfer a separate action after successful build.

## Regression and release checks

- Unit/synthetic tests: GP4 escaping/path resolution and malformed XML; SFO
  serialization; writer layout/crypto known answers; missing resources; binding
  changes; mismatch/delta/downgrade refusal; merge metadata/deletion rules.
- Failure tests: truncated inputs, arithmetic/offset limits, disk-full/short writes,
  cancellation by phase, source changes, output aliases, existing outputs and
  scratch cleanup. Never damage an original or publish incomplete output.
- Reference checks: independent readers/integrity validators and manifests/hashes;
  our reader alone is not the oracle. Keep actual console checks distinct from
  structural checks and describe reference-tool limitations.
- Run formatting, warning-free Clippy and workspace tests. Recheck inspect,
  extraction, trophies and existing ZAR conversion after shared-reader/SFO changes.
- Update README, compatibility matrix, fixture instructions and authoring support
  table per accepted stage. Record Linux-only, synthetic-only and hardware-untested
  limitations; do not announce later stages as implemented alongside the writer.
