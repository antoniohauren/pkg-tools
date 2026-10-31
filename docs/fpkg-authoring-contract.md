# Stage 1: native FPKG authoring contract

Research: 2026-10-30/31. Minimal SFO serialization and narrow base GP4 API/CLI implemented; no native PKG writer or remarry command
implemented, no game packages changed, no console compatibility established.
This supplements [the implementation plan](fpkg-authoring.md), not the existing
[extraction contract](extraction.md) or ZAR contract. Base/update merging is deferred.

## Evidence and reference policy

Labels below distinguish **source-confirmed** behavior (what inspected code does),
**fixture-confirmed** results (already executed extraction comparisons), **policy**
(our proposed narrow contract), and **open/hypothesis** (not established).
Source-confirmed reference behavior is not a universal PS4 requirement.

| Pin | Inspected source and purpose | Limits |
| --- | --- | --- |
| **L**: maxton/LibOrbisPkg `643477263b2644e0803e0f58b8726ea4e3f3b7d4` | [source tree][L], especially `LibOrbisPkg/{PKG,PFS,GP4,PlayGo,Rif,Util}` | LGPLv3 (`LICENSE.txt`). Base writer/GP4 and partial validator reference; not a working full-update binding oracle. |
| **F**: flatz/pkg_pfs_tool `4e74afa98b0f57b2b50a2182c1ef89905dc040a7` | [source tree][F], `src/{pkg,keymgr,pfs,pfs_io,crypto,main}.c` | Independent crypto/read reference already pinned for extraction. No top-level license grant found; do not copy source or redistribute its bundled libraries/keys without review. Not a directory-to-PKG writer. |
| **O**: OpenOrbis/LibOrbisPkg `92a4e7f8e5914cb06b52ba3ae6b0675da438a051` | [source tree][O], `LibOrbisPkg/PKG/{PkgBuilder,PkgProperties,PkgValidator}.cs` | LGPLv3; additional fork inspected, same missing selected-base input/patch-binding limitation. Same lineage, not an independent second format implementation. |

All references are research/test oracles only. Implement format logic independently
in native Rust; no copied reference implementation, linked C# library, bundled EXE,
or subprocess runtime dependency. Existing Rust crypto primitives remain the starting
point. Writing needs additional numeric inputs (L `Util/Keys.cs`: seven package public
moduli, fake-sign modulus aliasing slot 3, debug-RIF key material and keystone HMAC constants).
Existing read-side fake/DK3 primes are not that complete inventory. Record provenance
and review distribution/file-level licensing before adding constants; no secret
fixture material or passcodes in documentation, logs or committed fixtures.

Follow-up 2026-10-31: [synthetic base oracle][tests] now builds and reads a bounded
GD base, passes 27 emitted reference checks and independent keyless hashes, detects
PFS-image corruption, and matches native extraction (8 files / 3 directories).
This is not all-block PFS authentication, runnable-homebrew or console evidence.
[Numeric-input provenance review](fpkg-authoring-provenance.md) inventories required
symbols and historical leads; distribution authority remains unresolved. No new
authoring constants are copied into this repository.

Local-code audit baseline: `737be5d1762fa47760e247e5b0980fce95f576c9`, plus the
pre-existing working-tree authoring plan. Relevant paths:
`crates/ps4-pkg/src/{lib,crypto,extract,pfs,pfsc}.rs`, `crates/psf/src/lib.rs`.
Existing `PLAN.md` and authoring notes were already modified/untracked before this
investigation; unrelated work is not replaced.

## 1. Chosen writer profile and container construction

**Policy: first executable target is synthetic/homebrew GD base only**, with an
explicit build passcode, already prepared executable bytes, SFO 1.1, ASCII paths,
regular files/directories, one image, one install chunk and one scenario. Preserve
empty directories. No retail/DLC/remaster/delta, split images, symlinks, per-file
compression, multi-disc, custom PlayGo or unsupported settings. Application inputs
include `eboot.bin` and `sce_sys/param.sfo`; this is our preflight requirement, not
proof those two files alone make a runnable title. Existing-game rebuilding remains
gated on the resource inventory below. Full-update target remains GD + `CATEGORY=gp`,
same title/content ID, complete non-delta update against an explicit base; its
emission profile is **blocked**, not replaced by L's DP behavior.

### Source-confirmed minimal base layout

L `PKG/PkgBuilder.cs:246-466` (`BuildPkg`), `PkgWriter.cs:28-115` and `Entry.cs`:

* Big-endian CNT header; body starts `0x2000`. Initial six system entries are
  ENTRY_KEYS (`0x10`), IMAGE_KEY (`0x20`), GENERAL_DIGESTS (`0x80`), METAS (`0x100`),
  DIGESTS (`0x1`), ENTRY_NAMES (`0x200`), in that **physical allocation order**.
  METAS records are subsequently sorted by ID; name offsets are allocated in
  name-sorted order. Do not confuse physical ordering with table ordering.
* Entry data aligned to 16 bytes; body end/outer PFS start aligned to `0x80000`.
  Initial table offset `0x2a80` is a consequence of the preceding system records,
  not permission to hardcode it for every profile. Check all computed offsets,
  table counts and 32-bit entry offsets/sizes before narrowing.
* App volume maps to GD `0x1a`, DRM PS4 `0xf`, header flags `0x1`, content flags
  `Unk_x8000000 | GD_AC = 0x0a000000`; PFS flags `0x80000000000003cc`, one image, signed size
  `0x10000`, cache size `0xd0000`. Fixed version date/hash are `0x20161020` /
  `0x01738551` in L. These are reference profile constants, not SFO `APP_VER` or
  verified minimum-firmware rules. Promote size is body end; mount-image size is
  set to total package size by L. Unknown field meanings remain unknown.
* Generate debug `license.dat` (`0x400`), `license.info` (`0x401`),
  `psreserved.dat` (`0x409`, zero `0x2000` bytes), SFO (`0x1000`), and GD PlayGo
  records (`0x1001..0x1003`). Include recognized supplied application metadata
  exactly once in its correct namespace. L's top-level-only resource loop is not
  a sufficient nested `sce_sys` inventory for this project.
* Base/full-update identity policy: header content ID must agree with SFO;
  preserve `TITLE_ID`, `CONTENT_ID`, `APP_VER`, `VERSION`, category and firmware
  fields unless an explicit documented operation changes them. Version syntax,
  downgrade checks and base-version semantics need tests before update support.

Source-confirmed generated-entry serialization (L `PkgBuilder.cs:395-441`,
`Entry.cs:207-245,370-429`; key index from flags2 bits 12..15):

| Record | Flags1 | Key index | Declared size |
| --- | --- | --- | --- |
| ENTRY_KEYS | `0x60000000` | 0 | `0x800` |
| IMAGE_KEY | `0xe0000000` | 3 | `0x100` |
| GENERAL_DIGESTS | `0x60000000` | 0 | `0x180`, type `0x100` |
| METAS | `0x60000000` | 0 | `entry_count * 0x20` |
| DIGESTS | `0x40000000` | 0 | `entry_count * 0x20`; first/self slot zero |
| ENTRY_NAMES | `0x40000000` | 0 | ASCII NUL-terminated strings, initial empty name |
| LICENSE_DAT | `0x80000000` | 3 | `0x400` |
| LICENSE_INFO | `0x80000000` | 2 | `0x200` |

Each table record has six BE32 fields (ID, name offset, flags1, flags2, data
offset, data size), then eight zero bytes. Alignment padding is outside declared
entry length. Generated SFO/PlayGo/reserved and supplied resource records use zero
flags in this base writer. Check mirrored `u16` entry count as well as `u32`
offset/size limits; reject overflow before output allocation.

**Important counterexample:** L `PkgBuilder.cs:491-530` maps `pkg_ps4_patch` and
`pkg_ps4_remaster` to DP `0x1e` + `SUBSEQUENT_PATCH` (with TODO). `PkgProperties.cs`
has no selected-base field and `FromGp4` forwards none. F `src/pkg.h` distinguishes
GD app/patch/remaster from DP delta; current `open_game` accepts only GD without
the delta bit. L's patch output therefore cannot be our full-update recipe or be
read back through our supported extraction profile. Do not loosen extraction to
hide this discrepancy. Exact supported first/subsequent/cumulative update flags
remain a fixture/oracle gate; enum names alone are not semantics.

### Images, crypto and generated integrity records

Source locations: L `PFS/{PfsProperties,PFSBuilder,FSTree,PFSCWriter,FlatPathTable}.cs`
(`CollisionResolver` is declared in `FlatPathTable.cs`),
`PKG/{Entry,Pkg,PkgBuilder}.cs`, `Util/Crypto.cs`.

1. Inner PFS: v1/magic 20130315, 64 KiB blocks, unsigned D32, clear; super-root,
   `uroot`, `flat_path_table` and conditional `collision_resolver`, inodes,
   directories, padding and block allocation are **generated**, not application
   files. L applies a base minimum `0x55` blocks. Reproduce verified lookup-table
   hash/collision behavior; successful directory traversal alone does not test it.
   L `FlatPathTable.cs:16-113` uses wrapping `h = 31*h + uppercase(c)` over
   slash-prefixed relative paths, sorted unsigned hash/LE32 inode pairs. Directory
   inode values carry `0x20000000`; collisions use `0x80000000 | resolver_offset`
   and full-path resolver dirents. ASCII policy avoids culture-sensitive uppercase.
   Case-unique paths can still hash-collide. Multi-block lookup tables and inode
   block rollover need vectors, not an unchecked translation of reference offsets.
2. Initial profile always wraps inner PFS in **raw-block PFSC**, not optional
   omission: L `PFSCWriter` emits header, `0x400` offset-table pointer, N+1 LE64
   offsets, 64-KiB-aligned data start and raw 64 KiB blocks. No DEFLATE compressor
   needed initially. Our reader currently requires PFSC here; compressed PFSC is
   later work, not equivalent to per-application-file compression.
3. Outer PFS is signed S32 + encrypted, 64 KiB blocks, `uroot/pfs_image.dat`.
   L `FSTree.cs:155-166` sets outer image inode size fields/`Compress` for PFSC;
   do not interchange logical inner length with stored wrapper length. L uses a
   zero seed and legacy/passcode-derived key route. That is an explicit reference
   profile, **not** fallback material for an unknown base. Its allocator leaves
   a special clear zero block (`PFSBuilder`'s `emptyBlock`); validate this exception
   independently before adopting it as required layout.
4. Let `D[i] = SHA256(SHA256(BE32(i)) || SHA256(content_id padded to 48) ||
   passcode32)`. Legacy image key is `D[1]`. Entry keys store seed digest plus
   seven `SHA256(D[i]) XOR D[i]` digests and RSA-wrapped keys; slot 0 wraps the
   passcode bytes instead. IMAGE_KEY wraps image key using FakeKeyset public
   modulus, then receives entry encryption with D[3]. This is **not** evidence
   an arbitrary original passcode can be recovered.
5. PFS encryption/sign keys use HMAC-SHA256(image key, `LE32(index) || seed16`),
   index 1 for XTS (first 16 tweak, last 16 data), index 2 for HMAC. XTS sectors
   are 4096 bytes with image-relative numbering; header block stays clear. Build
   HMACs over plaintext padded data blocks, then indirect blocks, then inode
   blocks/header in dependency order, **before encryption**. Signed block refs
   contain HMAC32 + LE32 block number. Header HMAC uses zeroed hash/signature
   area and `0x5a0` coverage as specified in [extraction corrections](extraction.md).
6. New-crypt inputs are a separate read-side case: F `src/keymgr.c` / `src/pkg.c`
   establish that unwrapped IMAGE_KEY already includes the seed transform.
   Current Rust correctly does not apply it twice. Do not copy input PFS flags
   onto a legacy-route build without proving matching derivation.
7. Encrypted metadata key/IV is SHA256(serialized **final** 32-byte table record
   || D[key index]), first half IV/last half AES key. L uses key index 3 for
   IMAGE_KEY/license.dat, **2 for license.info**. General tail rule is CBC full
   blocks plus CFB tail, not padded stored lengths (F `src/crypto.c`; current
   extraction vectors). L's helper implements only aligned CBC despite its name.
   Moving/reflagging encrypted records requires re-encryption, not ciphertext copy.
8. Generate PlayGo one-chunk DAT and default manifest (L `PlayGo/ChunkDat.cs`,
   `Manifest.cs`); update physical/inner sizes after layout. SHA record contains
   first four SHA256 bytes for each 64 KiB package block in the PFS range, indexed
   by package-relative block number; preceding slots remain zero in L. Custom
   chunk/scenario/language scheduling is not supported initially.
9. Finalize PFS first-block/full-image SHA256; general digests; encrypted body;
   table-indexed stored-entry hashes (skip DIGESTS self-hash); body/table hashes;
   two SC-entry aggregate hashes; header; SHA256 of `[0,0xfe0)` at `0xfe0`;
   fake signature at `0x1000` from SHA256 of `[0,0x1000)`. L `Pkg.cs:126-209`
   defines major-param/content/header digests; preserve exact input serialization,
   not a guessed concatenation of display values. GeneralDigest GameDigest is
   **that package's PFS image digest** in this code, not proven base linkage.
10. L's `RSA2048EncryptKey` is deterministic SHA256/MT-generated nonzero type-2
    padding and public modular exponentiation, including for the so-called fake
    header signature. It is not standard private-key signing or authenticity.
    Debug RIF uses separate secret AES and real PKCS#1 SHA256 RSA signing with
    `DebugRifKeyset` (`Rif/LicenseDat.cs:15-79`). Known-answer vectors and independent
    verification are required for both; ordinary Rust RSA signing is not a drop-in
    replacement for the fake-header construction.

## 2. Metadata ownership and rebuild readiness

**Policy:** separate application tree from authoring inventory. Do not expand or
silently alter existing extraction/ZAR output. A future authoring-only read path
must inventory container resources and reject unknown required records.

| Artifact | Base rebuild | Full update / remarry | Evidence and limits |
| --- | --- | --- | --- |
| Executables, modules, application data, empty dirs | Preserve decoded payload bytes | Preserve update payload bytes; no base-tree copy | Current `Game::read_entry`; authoring does not decrypt/rewrite SELF or backport firmware. |
| SFO game identity, category, versions, attributes, firmware, unknown fields/types/capacities | Preserve | Preserve `gp` and update version; reject mismatched title/content IDs | `psf::parse` retains used bytes/padding; `psf::serialize` preserves semantics for SFO 1.1. No general edit API/UI. |
| `PUBTOOLINFO`, `PUBTOOLVER` | Regenerate only with documented build summary | Same, after binding recipe is known | L `PkgBuilder.cs:319-344` sets date/time/image-size info and `0x02890000`; not a firmware-backport operation. Exact values are reference-profile choices pending oracle tests. |
| Base `sce_sys/keystone` | Preserve byte-for-byte for existing games; missing is error | No synthesized/base-only keystone copied into update; unexpected update keystone blocks preflight pending explanation | L `PfsProperties.MakeInnerPFSProps`, `Crypto.CreateKeystone`. New homebrew generation requires explicit policy, not silent replacement. |
| `nptitle.dat` (`0x402`), `npbind.dat` (`0x403`) | Preserve/inventory outside normal extraction | Preserve update resources; do not substitute base's whole `sce_sys` | F `src/pkg.c` entry map; L enums. Current extraction drops IDs below `0x1000`. Necessity/validation and rebuild placement need dedicated NP research; never classify these as disposable digests. |
| Trophy TRPs, localized assets, icons, sound, manuals, save/share resources | Preserve correct source bytes | Preserve update-owned resources and associations | `metadata_name` in `extract.rs`; nested metadata relocation must be explicit. No trophy authoring or invented NP identity. |
| Runtime PlayGo DAT/SHA/XML and `sce_sys/app/` variants | Regenerate layout-dependent records for chosen single-chunk profile | Regenerate only when update contract established | Extraction intentionally preserves these bytes. L's creator skips generated records, while builder unconditionally generates GD defaults: reject unsupported custom PlayGo rather than claim faithful rebuild. |
| Keys, licenses, general/table/body/header digests, fake signatures, PFS/PFSC internals | Regenerate for output identity/layout | Regenerate, with verified selected-base binding | Not application files; copying stale values cannot validate a rebuild. Unknown imageinfo/selfinfo/other records must be classified or rejected, not blindly zeroed. |
| Patch-only disc maps/linkage | Reject in initial base profile | Generate only from verified binding recipe | No established writer in inspected sources; opaque copy may retain old base binding. Merge treatment deferred. |

**Source-confirmed keystone construction:** L `Crypto.CreateKeystone` emits 96
bytes: 32-byte versioned header, HMAC(passcode) fingerprint with
`keystone_hmac_key`, and HMAC(header || fingerprint) with `keystone_mac_data`.
L only auto-adds one for app projects. **Open:** preserving keystone, SFO save
fields and NP resources is necessary conservative policy, not proof old saves
survive reinstall/rebuild or update remarry. Neither reference construction nor
extraction demonstrates console save ownership rules. Keep save-backup warnings;
do not offer identity regeneration as a repair for existing games.

**Fixture-confirmed extraction is not rebuild evidence:** two local fixtures
already matched all 4,583 files / 1,483 directories and 44 container records /
50 SFO values against the adapted pinned reader. See [reference results][tests]
and [coverage](extraction.md). No authoring comparison was run in this stage.
Those two fixtures alone are not an established incompatible-binding pair.

Current gaps, confirmed in local source:

* `Header` omits PFS image/signed digests, general digests and most full header
  fields. `Package::open` temporarily reads `0x5a0` but exposes only selected
  fields. Entry listing exposes offsets/flags, not a general bounded/decrypted
  authoring-record API at the original audit baseline. The package-source milestone
  below now retains the full raw header and provides bounded authoring record reads;
  `Game` itself still loses container/header inventory after enumeration.
* `crypto::recover` returns only DK3 and ready image key internally, checks DK3
  digest; no passcode, D[0..6], key-2/license.info recovery or update-binding API.
  `Pfs::open` checks header HMAC, not every signed data/indirect block.
* `extract.rs::metadata_name` restores recognized application IDs >= `0x1000`;
  IDs below that, including NP records, are intentionally omitted. Keystone is
  available only if actually present in inner PFS. Files/mode/timestamps/layout,
  unknown container semantics and original GP4/chunk rules are not losslessly
  represented by an extracted directory. Unknown application IDs already fail.
* `psf` borrows entry raw bytes, format, capacity and padding; it does not retain
  every original offset/table gap/trailing byte. Parse/write semantic preservation
  is achievable, but exact whole-file preservation requires retaining original
   SFO bytes. `psf::serialize` implements this semantic preservation. Do not promise byte-identical
  reserialization of arbitrary input from `Sfo` alone.

## 3. Base/update binding: explicit stop gate

**Confirmed:** matching TITLE_ID/CONTENT_ID is necessary scope validation, not
proof of marriage. Readers open supported base and update independently with
public fake-key recovery; they perform no selected-base binding comparison.
Recovered ready image key is enough for read-side PFS, not proof of the original
passcode/D[1] on new-crypt inputs or availability of every writer key.

**Not established:** exact selected-base digest(s), record offsets, key/passcode
dependencies and transformations needed to author a working full update.
L has no base input; normal CLI `pkg_build` rejects patch projects outright
(`GP4/Gp4Validator.cs:89-104`, `PkgTool/Program.cs:59-92`). Its lower-level patch
branch is not a supported build path. `CalcGeneralDigests` writes the package's own image digest;
origin/target digest enum names do not implement binding. Its validator explicitly
skips unknown general digests. O has the same limitation. F is useful for decoding
but is not a from-directory update builder. Consequently **there is no verified
binding recipe in this contract and remarry stays blocked**. Do not substitute
zero keys, assume equal passcodes, rewrite title IDs, copy an opaque old link,
or claim changing GameDigest is sufficient.

More specifically, L `Entry.cs:406-441` reads origin/target slots but its writer
never serializes them, even if their dictionary values are set. `Pkg.cs:195-209`
generates only Header/Game/Content/MajorParam/Param digests (AL omits Game).
`PkgValidator.cs:118-129` describes origin/target algorithms as `???`. Neither
whole-file SHA256 nor base header/PFS digest can be substituted on that evidence.

Minimum research input for unblocking: a permitted same-title/content-ID base A
and base B with demonstrably different binding, an update for A, and independently
built update output explicitly targeting B (plus exact builder/version/settings).
Capture private hashes/record manifests before and after. Compare full headers,
general digests, decrypted container metadata, patch disc maps, PlayGo, SFO and
unchanged payload hashes. Perturb one base property at a time on synthetic inputs
where possible. Identify every changed binding field and derive it from B; prove
the old pair fails for binding rather than unrelated firmware/executable reasons.
Until that exists, neither the current extraction fixtures nor “open succeeded”
establish a remarry test.

If an eventual recipe requires original passcode or a nonrecoverable derived key,
require that explicit input and validate it against available key digests before
output. No current public API supplies it. It is also **not yet confirmed that a
passcode is required**: record that as an unresolved question, not a requirement
disguised as fact. A new output passcode for a new base is a separate choice from
preserving an installed game's keystone/save identity.

Full-update deletion/opaque semantics and merge metadata remain gated separately.
L `Gp4Project.DeleteFile/DeleteDir` (`:144-168,198-206`) removes manifest mappings,
not tombstones. `PfsProperties.BuildFSTree` has only one input tree;
`PfsStructs.cs:567-584` defines file/directory/dot/dotdot dirents, and the builder
emits those ordinary kinds, not whiteouts. **Confirmed absence in that build path
is not proof of absence in console full-update semantics.** Missing update paths
must never be interpreted as deletions without evidence. Opaque directories,
type changes and previous-update replacement need separate evidence before merge.

F does declare `PFS_FILE_TYPE_WHT = 0160000` / `PFS_IS_WHT`
(`src/pfs.h:63-73,100-109`), so a blanket “PFS has no whiteouts” claim is false.
Its GP4 exporters accept ordinary file/directory entries and ignore flags
(`src/gp4.c:174-208,419-441`); that does not establish how a full update encodes
deletion or opaque directories. Current Rust rejects such special inode types.
Keep that refusal until semantics and representative fixtures are verified.

## 4. Initial GP4 subset

**Implemented 2026-10-31:** `ps4_pkg::gp4::Project` generates, parses and writes
this standalone-app subset. `parse` validates XML/model only; `preflight` validates
sources and SFO under an explicitly approved absolute source root. `write_new`
repeats preflight and publishes only at the original project location, so changing
output location cannot silently rebase source paths. `to_xml` is serialization,
not source approval. CLI `gp4 create` uses that same library path.

GP4 is a native module beside authoring in `ps4-pkg`, not a new build framework.
L `GP4/Gp4Project.cs:12-107,217-268,275-513` defines this XML model; reading uses
`XmlSerializer`, not schema/feature validation. `PkgProperties.FromGp4` forwards
only identity/passcode/type/dates/tree, not arbitrary project settings.

| Field | Initial native contract (policy) |
| --- | --- |
| Root | `psproject fmt="gp4" version="1000"`; one `volume`, `files`, `rootdir`. Reject other formats/versions. |
| Volume | `pkg_ps4_app` builds; `pkg_ps4_patch` is the planned full-update project role, not permission to emit DP. Preserve optional volume ID, require valid explicit timestamp and define UTC conversion without host-locale/DST dependence. |
| Package | 36-byte validated `content_id` consistent with SFO, explicit 32-byte ASCII `passcode`, `storage_type="digital50"`, `app_type="full"`. No implicit zero passcode. Reject entitlement keys/add-on settings in this profile. |
| Dates | Preserve/import explicit `c_date` date or date-time; resolve `actual_datetime` once at build start if supported. Report resulting PUBTOOL edits. Do not inherit L's locale-sensitive DateTime parsing/DST bug. |
| Install metadata | One chunk 0, layer 0; one default scenario 0, type `sp`, initial count 1, chunk list `0`. Preserve labels. Reject nondefault scenarios, language scheduling, extra images/layers/chunks. L's builder ignores custom GP4 scheduling and always creates defaults. |
| Files | `files img_no="0"`; explicit `file targ_path="..." orig_path="..."` only. No wildcards, compression flags, per-file chunk assignments or deletion directives. Our emitter always supplies `orig_path`; L defaults a missing one to target path, which must be handled explicitly or rejected on import, not resolved against cwd. |
| Directories | `rootdir` with nested `dir targ_name="..."`; preserve empty dirs and emit all target parents. Reject duplicate declarations/collisions and inconsistent hierarchy. L needs explicit parents because `BuildFSTree.FindDir` looks them up. |
| Update base | Mandatory explicit base-package reference in future update projects. **Encoding/field name and interoperability are not yet pinned:** L `PackageInfo:351-369` models no base reference (including no `app_path`). Do not invent XML and call it compatible. Block update emission/import of unsupported binding settings until a primary implementation/oracle establishes them. |

**Supported initial interoperable subset is standalone app GP4 only.** Next-stage
patch model/generation must wait for its base-reference contract; recognizing a
patch enum is not build/round-trip support. L `SetType` throws for patch;
`Gp4Creator`'s DP mapping does not overcome that. The planned stage-2 exit covering
base **and update** GP4 cannot currently be satisfied with L alone.

XML uses the already-reviewed `roxmltree` 0.21.1 (MIT OR Apache-2.0), default
`std,positions` features, with no new external resolved versions. Bound XML bytes/depth/counts, disable DTD/entities,
validate all destinations/case/file-directory collisions and reject symlinks/special
input kinds before writing. Source/base paths resolve relative to GP4 location;
external/absolute sources must be surfaced in preflight and require explicit source
policy approval. Emit relative references where practical. Unknown build-affecting
elements/attributes must fail with their names; neither XML preservation nor L
silently ignoring a field establishes execution support. Generate identity/version
from SFO, never directory names, without changing source files.

### Executable subset and limits

* Only the elements/attributes in the table above are accepted; all fixed fields
  and one-chunk/one-scenario values are required. Optional `volume_id` and `c_date`
  are retained; chunk/scenario labels are required and retained. Namespace-free
  elements/attributes only (unused namespace declarations from .NET serialization
  are harmless). Comments are ignored, not round-tripped; XML formatting/order is
  normalized. Unknown settings fail with their element/attribute names.
* `volume_ts` is exactly `YYYY-MM-DD HH:MM:SS`; `c_date` uses that or `YYYY-MM-DD`.
  Gregorian dates, years 0001–9999, interpreted as UTC; date-only means midnight
  UTC for any future consumer. No locale, DST conversion or `actual_datetime`.
  There is no build or PUBTOOL edit at this stage.
* Content ID profile is `[A-Z]{2}[0-9]{4}-CUSA[0-9]{5}_[0-9]{2}-[A-Z0-9]{16}`.
  SFO 1.1 must contain text CONTENT_ID/TITLE_ID/CATEGORY/APP_VER/VERSION;
  IDs must agree, CATEGORY must be exactly `gd`, both versions use `NN.NN`.
  Version values are reported by preflight, not invented as GP4 fields. GP4 is
  only a manifest: supplied NP/trophy/PlayGo files are mapped unchanged, not
  classified as rebuild-ready or supported for a future PKG writer.
* Limits: 8 MiB UTF-8 XML, 100,000 XML nodes, depth 64 (including document node),
  32,768 combined mappings/directories, 4096 bytes per target/source/label/volume ID,
  target depth at most 60; SFO read capped at 16 MiB. DTD/entity declarations
  rejected; ordinary predefined/numeric XML escapes supported. Emitted XML must
  satisfy import limits too. File payloads are not read into memory.
* Destination components follow `pkg_fs::valid_component` (portable ASCII).
  Every parent must be explicitly declared with exact case. Duplicate declarations,
  case collisions and file/directory collisions fail. Empty directories retained.
  Sources use forward-slash Linux paths, explicit `orig_path`; no wildcard/drive
  syntax. Relative sources resolve only from the supplied absolute GP4 location.
* `source_references` reports resolved paths and absolute/outside-project flags
  even before approval. `preflight(root)` explicitly approves references beneath
  that one root, including external/absolute references; anything outside fails.
  Symlinks in source/root components, special files and missing files fail.
  Sources must remain stable during these operations: like current directory
  packing, this metadata-based policy is **not a hostile concurrent-mutation
  sandbox**. No future payload reader may assume preflight makes later I/O safe.
* Output must be outside the approved source root; parents must exist and cannot
  contain symlinks. Scratch-and-hard-link publication never replaces an existing
  file, symlink or hard-link alias; failures clean unpublished scratch best-effort.
  Hard-link support is required. Native Unix GP4 output is owner-only (0600).
  Passcode must be explicit 32 printable ASCII bytes; no default, no Debug output.
  GP4 XML necessarily contains it and must stay private. No cancellation/progress
  API or input-stability snapshot yet: bounded manifest work only, not a build.

Executed pinned-L round trip: native CLI generation of 9 synthetic files / 4
directories (including escaped names and empty directory), reference ReadFrom,
BuildFSTree and WriteTo, then native parse/preflight plus settings/mappings/identity
equality. Optional volume ID/date and nondefault labels are additionally exercised
by a synthetic supported-settings variant in the harness. This is schema-subset
interchange evidence only, not official-tool, PKG-build, NP/trophy or console support.

### NP/trophy oracle limitation

L `PKG/Enums.cs:701-702,726,747-754` maps NP and nested trophy/changeinfo names,
but `PkgBuilder.cs:379-385` only visits immediate `sce_sys` files. Supplied NP files
are copied; nested trophies remain inner-PFS files instead of being promoted to
their mapped container records. `CalcGeneralDigests` never sets TrophyDigest;
`PkgValidator` describes it as `???`. `Gp4Creator.cs:59-97` can extract nested
records, so its rebuild path is asymmetric. Our writer must not reproduce this
as a claim of correct NP/trophy support. Initial synthetic base profile excludes
NP/trophy-bearing authoring until placement/identity validation is established;
real-title rebuilding remains gated. Do not fabricate dummy NP files or claim
they are universally optional. Their signatures, trophy associations, registration
and save effects need an independent resource/console test.

## 5. Validation plan, not compatibility claims

### Native signed/encrypted outer image (2026-10-31)

`ps4_pkg::outer_image::OuterImage::new(&inner, unix_timestamp)` plans actual S32
signed/encrypted PFS containing `uroot/pfs_image.dat` (raw PFSC). `write` takes
empty readable/writable seekable scratch at offset zero, an explicit ready 32-byte
image key, the same bounded inner payload callback and cancellation closure.
`write_new` publishes only `.pfs`, owner-only/no-overwrite, with one image's scratch;
`.pkg`/`.pfsc` fail. Partial stream output must be discarded on any error.
No PKG writer, RSA operation, new fixed key or production dependency.

`outer_image::legacy_image_key(content_id, passcode)` validates the existing GP4
content-ID profile and 32 printable ASCII passcode bytes, returning sensitive
`D[1]`. Passcodes are not hex-decoded. No default, recovery, logging or new-crypt
transform. Callers may use `project.content_id()` / `project.settings().passcode`;
the ready-key writer does not accidentally derive/transform an unwrapped key twice.

Unix `authoring::PreparedProject::{outer_pfs_size, write_outer_new}` reuses approved
GP4 placement and source validation. All source bytes (including excluded metadata
and empty files) are rehashed before scratch and after signing/encryption/sync,
before publication. Same no-follow opens, source-stability limitations and stable
destination-parent requirement as `write_inner_new`. No CLI key input introduced.
Output is not a self-contained application: container resources remain absent.

Profile evidence: pinned L `PFS/PFSBuilder.cs:352-443`, `PfsStructs.cs`,
`PfsProperties.MakeOuterPFSProps`, `FSTree.cs:155-166`, `Util/Crypto.cs:17-47,291-304`;
independent F `src/keymgr.c:381-480` corroborates legacy derivation/key ordering.
[Parallel crypto findings](crypto-unblocking-findings.md) narrow outer-layer gates,
independently authenticate reference-produced small output and document the S64
header-reference stride trap. Native output is independently checked separately.

Implemented profile:

* 64 KiB blocks, four S32 inodes, superroot/lookup/uroot; image inode compressed flag,
  `Size=PFSC length`, `SizeCompressed=inner PFS length`. Explicit zero seed is legacy
  profile parameter, never a fallback key. All four timestamps explicit.
* Direct, single and double signed references. Maximum payload block count
  `12 + 1820 + 1820*1820`; larger images fail before I/O. No triple/64-bit inode
  variants. >4-GiB arithmetic/layout tested, not actual large-file throughput.
* Sequential PFSC into final scratch; plaintext padded data HMACs, indirect leaves/
  parent, inode block, then header. Header covers `0x5a0` with `[0x380,0x5a0)` zero.
  Refs are HMAC32 + LE32 block index; sole header inode-block ref is S64 (40-byte
  layout, not upstream allocator's erroneous 36-byte multi-ref stride).
  Indexes stay on disk; bounded 64-KiB buffers, no payload-proportional RAM.
* HMAC-SHA256(image key, LE32(index) || seed16), index 1 tweak/data halves,
  index 2 signing. AES-XTS sectors 4096 bytes, image-relative LE128 numbers.
  Header and reference's **unreferenced clear zero block 4** remain clear.
  Independent checks establish this profile, not universality of that exception.
* Cancellation between block reads/writes/HMAC/encryption and before publication;
  I/O/source errors propagate, scratch cleans best-effort. Existing outputs/sources
  never replaced; hard-link support required. Supplied symmetric keys permit HMAC
  recomputation; unreferenced padding/header tail is not authenticated. No vendor
  RSA signature/authenticity claim follows from PFS HMACs.

#### Independent crypto known answers and origins

New vectors are standards data or original **public synthetic inputs**, never
game keys/passcodes/private fixture fingerprints:

| Test | Origin/input | Independent verification |
| --- | --- | --- |
| HMAC-SHA256 | [RFC 4231 section 4.2](https://www.rfc-editor.org/rfc/rfc4231#section-4.2), case 1, key `0b` repeated 20, ASCII `Hi There` | Published full MAC, Rust assertion |
| AES-128-CBC | [NIST SP 800-38A](https://doi.org/10.6028/NIST.SP.800-38A), F.2.2, all four AES-128 blocks, no padding | Published key/IV/plaintext/ciphertext, Rust assertion |
| PFS material | Original key bytes `00..1f`, seed `00..0f`, indices 1/2 | Python hashlib/hmac + pinned L + Rust agree on `76be34e86d4a3793c4f2af46f63879f41b876753b3609b58c497052fc4f416b6` / `e9d9d5c076c2b31e0a95557f14f36f20b99cfcc788f7c09e640ada5f49eeb7bd` |
| XTS sector | Previous index-1 material, plaintext byte `i % 251`, length 4096, sector 16 | Python OpenSSL-backed cryptography ciphertext SHA256 `af5cd198566f2d9370dfaf633d7c52c32e84f9390fadc8f16e0947d55a63b092`, first32 `ceed998c169a81d5e1ea5c383d78f1eb6999d121bddec95ecb297ec0865a6d70`; Rust asserts both |
| Full legacy chain | [Findings' public synthetic recipe](crypto-unblocking-findings.md#reproducible-public-synthetic-known-answers): explicit synthetic content ID/passcode, D[0..6], zero/ascending seeds, sector19, padded-block HMAC | All seven published SHA256 values asserted by Rust, Python/OpenSSL and pinned L harness; no new fixed format secrets |

Reproducer: `tests/reference/check-outer-image.py`, `OuterImage.cs`, and
[reference instructions][tests]. Python independently decrypts every sector and
checks every referenced padded-block HMAC, allocation/nonaliasing, lookup, namespace,
PFSC index and patterned inner bytes; flips each referenced block and header to
demonstrate mismatches. Pinned L traverses outer/PFSC/inner and compares all file
bytes. Both executed on single-/double-indirect native outputs (patterned file sizes
`13*65536+1`, `1835*65536+1`). Rust additionally tests wrong key, bounds, >4-GiB layout,
cancellation, I/O errors, scratch cleanup, output race and GP4 excluded-source mutation.
Python may buffer entire bounded synthetic output; native writer does not.

Unresolved: metadata-encryption writer vectors, deterministic RSA encoder/fake-header
and debug-RIF vectors; six additional package public moduli/debug-RIF/keystone input
provenance/distribution and writer-use decision for existing DK3-derived fake-header
modulus; homebrew keystone generation; licenses/PlayGo/container/final validation;
NP/trophy placement and update binding/remarry. No new fixed constants approved.
Reader still checks header HMAC only, not every traversed signed block; independent
oracle establishes emitted HMAC correctness, not native readback alone.
No full-PKG, hardware/install/launch/save, graphical or real >4-GiB check executed.

### Native GP4 source-to-inner-image pipeline (2026-10-31)

The next concrete dependency after image allocation is now implemented, without
crossing blocked crypto/container gates: Unix `authoring::PreparedProject` turns
the validated standalone-app GP4 subset into an actual clear `.pfs` or raw `.pfsc`.
CLI: `pkg-tools gp4 image PROJECT.gp4 OUTPUT.pfsc --source-root GAME_DIR`.
No `.pkg`, GTK, update/remaster/delta or new-homebrew-keystone generation.

Placement is deliberately narrow, source-confirmed by pinned L
`PKG/PkgBuilder.cs:379-385`, `PFS/PfsProperties.cs:MakeInnerPFSProps` and
`PKG/Enums.cs:EntryNames`, agreeing with existing native extraction names:

| Source | Placement |
| --- | --- |
| `sce_sys/param.sfo` | Container `0x1000`, original bytes; no PUBTOOL edits yet |
| `sce_sys/pic1.png` | Container `0x1006` |
| `sce_sys/icon0.png` | Container `0x1200` |
| `sce_sys/pic0.png` | Container `0x1220` |
| `sce_sys/snd0.at9` | Container `0x1240` |
| `sce_sys/keystone` | Inner PFS, original exactly 96 bytes, never regenerated |
| Ordinary application files and all GP4 directories | Inner PFS, preserve bytes/empty dirs |
| Any other `sce_sys` file | Refuse with target path; NP/trophy, supplied PlayGo and remaining system-resource validation stay gated |

Container resources remain represented by `resources()` and are available via
bounded `copy_resource(index, output, cancelled)` for future container assembly.
The standalone intermediate **does not contain them**: no image is advertised as
a complete application tree/package. No image/artwork/audio/executable format
validation, keystone authentication, NP association or save compatibility claim.
The conservative older inventory now recognizes the same supported artwork/audio
resources; other inventory/global blockers remain unchanged.

Source preparation validates the GP4 model and SFO identity from the exact bytes
being hashed. Explicit UTC GP4 timestamp becomes inode Unix seconds without host
locale/DST dependence. Approval requires resolved references under one absolute
source root; original traversal checks reject symlinks hidden by `..`. A pinned
root descriptor and per-component `openat` with `NOFOLLOW` prevent symlink traversal
on later payload reads; nonblocking final open plus regular-file checks refuse
special files. No unsafe code/new dependency/constants. Only one active payload
file descriptor; root/temporary traversal descriptors remain bounded too.

Each resource retains private SHA-256 plus device/inode, size, modification and
change times (nanoseconds). Hash pass checks exact length/EOF and before/after
metadata. Preparation rechecks the whole set; writing checks it before scratch,
hashes the actual streamed inner bytes, then rehashes **every** resource before
publication, including excluded metadata and empty files. Any detected replacement,
truncation, growth or change fails. Fingerprints/passcodes/keystone bytes are never
logged or Debug-formatted. This is multi-pass change detection, **not an immutable
snapshot or hostile concurrent-write sandbox**; keep inputs/output parents stable.
Final verification cannot atomically freeze all source paths until publication.

Payload/hash buffers are 64 KiB; SFO metadata additionally uses its existing 16 MiB
cap and path/layout metadata scales with existing GP4/image caps. Multiple full
source scans trade throughput for simple stability checks; no performance claim.
Cancellation is checked before/between entries and 64 KiB reads/writes, including
final verification; existing bounded GP4 model/traversal validation is synchronous.
CLI has no interactive cancellation control. Output must be outside approved root;
one image of owner-only scratch beside destination, sync, final source verification,
then existing hard-link/no-overwrite publication. Errors/cancellation remove scratch
best-effort, preserving all sources/existing outputs; parents must exist and stay
stable. Exact image bytes reported before writing; filesystem overhead is extra.

Executed native failure tests cover missing/wrong-size original keystone, unknown
resources, unapproved references, same-size mutations, empty-file changes, replaced
source symlinks, excluded-SFO mutation during writing, cancellation and scratch
cleanup. Shared no-follow source helper tests cover parent/final symlinks, directory
sources and escaping paths. Pinned independent L reads both generated synthetic
outputs: **5 inner files / 4 directories**, including boundary payload, empty entries,
keystone and `A~`/`B_` collision paths; all file bytes and directory/path sets match.
Five planned container resources are absent as intended. Separate Python checks UTC
timestamp, unchanged sources and refusal to replace each output. See [harness][tests].
Synthetic artwork/keystone bytes are opaque sentinels, not valid runtime resources.
No independent whole-PKG/crypto, graphical, hardware or actual >4 GiB check here.

### Native GP4 authoring-readiness milestone (2026-10-31)

`ps4_pkg::authoring::preflight(project, approved_root, cancelled)` and CLI
`gp4 preflight PROJECT.gp4 --source-root GAME_DIR` inventory approved GP4 sources
without writing a package. Existing `Project::preflight` schema/source/SFO checks
remain unchanged. The new report contains identity, every approved reference,
regular-file sizes, total source bytes, directory count, resource classifications
and explicit input blockers. It never contains the GP4 passcode, source hashes or
payload/key bytes. CLI success means inventory completed, not build readiness.

Classification is deliberately conservative: `param.sfo`, keystone, NP/trophy,
PlayGo/`sce_sys/app` and otherwise-unclassified `sce_sys` resources remain distinct
from ordinary application files. No supplied resources are dropped or rewritten.
Missing keystone blocks existing-title rebuilding; no implicit new-homebrew
generation policy is introduced. A supplied keystone must be 96 bytes; length is
not authentication or save-compatibility evidence. NP/trophy, supplied PlayGo and
unclassified system resources report blockers, not unsupported placement guesses.
The report always lists absent native writer, unresolved numeric-input provenance,
incomplete independent integrity/crypto vectors and hardware gates separately.

Work is bounded by GP4's existing limits; only the bounded SFO is read. No payload
scan, hash snapshot, scratch allocation, disk estimate or publication occurs.
Cancellation is checked before GP4 preflight and between inventory entries, not
inside existing bounded GP4 preflight. Sources must stay stable; a future writer
must reopen safely and verify input stability across its own passes. This is a
GP4-side portion of step 3, **not** completed package-source metadata inventory:
full header/general digests, decrypted bounded container records and explicit
encrypted key-index refusal tests were still required at that milestone.
No contract gate is waived; native image/container emission remains blocked.

### Native package-source inventory milestone (2026-10-31)

`authoring::preflight_package(Package, cancelled)` consumes a read-only package,
inventories every container record (generated, NP, application metadata or
unclassified), retains all `0x1100` header bytes including unknown fields/digests/
signature, and retains bounded decoded GENERAL_DIGESTS (`0x80`), NPTITLE (`0x402`)
and NPBIND (`0x403`) records. It enumerates the existing supported fake GD application
tree and retains the original keystone only when exactly 96 bytes. Missing/wrong-size
keystone and general digests, unknown low container IDs, NP/trophy, supplied PlayGo
and unclassified system resources remain blockers. Unknown application IDs still
fail through existing extraction validation; extraction/ZAR mappings are unchanged.

`Package::read_authoring_record(id, limit, cancelled)` reads at most the smaller
of the caller's limit and 16 MiB, checking before allocation. Reads/decryption use
64 KiB chunks and existing CBC/CFB-tail logic. Encrypted records support only the
already-public DK3 recovery route; other key indices (including license.info's 2)
and the unsupported encryption-algorithm flag fail explicitly. Generated license/
key records are classified, not retained as rebuild inputs or blindly decrypted.
No key-index substitution, new keys/constants or crypto provenance decision occurs.
At most three capped records plus one header/keystone and bounded record/tree
metadata are retained; payloads are not buffered or hashed.

CLI `fpkg preflight INPUT.pkg` prints counts, record IDs/roles/sizes/encryption
indices and blockers, never retained header/digest/NP/keystone bytes or hashes.
`PackageInventory` deliberately has no Debug implementation. Exit success means
inventory completed, not buildability. Original retained bytes are local sensitive
data, not public fixtures; general-digest retention is not digest verification.
This milestone does not validate header/SFO identity/version semantics, authenticate
NP/keystone, establish NP placement, or establish save compatibility. No payload
snapshot, scratch or publication. Sources must remain stable. Cancellation checks
precede I/O and run between chunks/entries and around `open_game`; existing bounded
tree preparation itself remains noninterruptible. Unknown required semantics and
all writer, provenance, integrity/vector, update-binding and console gates remain.

Synthetic tests cover retained bytes, NP omission from unchanged normal extraction,
unknown-record blockers, keystone missing/95/96/97-byte cases, successful index-3
decryption, key-index/algorithm refusals, allocation limits and cancellation. No new
independent package-source or hardware comparison is claimed.

| Tool / fixture | What it can establish | Unresolved gate |
| --- | --- | --- |
| Pinned L `PkgBuilder.Write(Stream)` through `Authoring.cs`; existing extraction adapter | Executed synthetic GD base build/readback, 8 files / 3 directories match native reader; SDK 8.0.425 | Not runnable homebrew; C# builder/reader share lineage. See reproducible [harness][tests]. |
| Native GP4 + pinned L `ReadFrom/BuildFSTree/WriteTo` | Executed standalone-app interchange, 9 files / 4 directories; native reparse/preflight and supported settings/mappings equality | XML subset only; no GP4 package build, official tools or update binding. |
| L `PKG/PkgValidator.cs::Validations`, plus Python keyless hashes | Executed 27/27 emitted checks Ok; independently recomputed container/image hashes and detected PFS corruption | Unknown/unset general digests skipped; harness rejects NoKey as well as Fail. Not a whole signed-PFS or console validator. |
| F `src/main.c` info/list/unpack; PFS/crypto readers | Independent byte/namespace and header/key cross-check | Not run this stage; `src/pfs_io.c` still has TODO ICV checks. Some signature checks warn or are disabled for unfinalized/fake inputs. Do not report full-block integrity from exit status. Do not dump keys in logs. |
| Existing Rust reader + extraction oracle | Regression check and native readback comparison | Same-reader acceptance alone cannot establish writer correctness or selected-base binding. |
| Generated synthetic fixture (local outputs only) | Small base structural build/read oracle, raw PFSC, boundary/empty file and empty directory | Non-executable eboot sentinel. No stable crypto known answers, large offset/collision or homebrew launch evidence; generated reference artifacts not approved for redistribution. |
| Private original/rebuilt base plus incompatible-binding update pair | Payload preservation, binding deltas and resource inventory | Acquisition/provenance and independent full-update build remain blockers. Existing local extraction fixtures are not this evidence. |
| Test PS4 | Installation, launch/version, trophies, new-save and existing-save load | No hardware tests run. Record firmware/tool versions and save backup/reinstall procedure separately. Emulator discovery is not a console result. |

Authoring fixture protocol: keep all game data, passcodes, key dumps and
title-specific manifests under ignored `pkgs/` or outside repo. Record source
fingerprints, exact reference commits, adapter diff hashes, GP4 settings, toolchain
versions and per-check results. Never modify originals. Compare all application
paths/sizes/SHA256, enumerate metadata edits, independently recompute container
digests and all outer block HMAC dependencies, and test corruption detection.
Before release exercise >4 GiB real files/offsets and bounded memory/scratch;
>100 GB, portability, custom NP/trophy/PlayGo, min-firmware behavior and all other
writer variants remain unclaimed. CyB1K's binaries are workflow context only;
no pinned/executed option-level authoring oracle was established here.

### Native clear inner-image writer (2026-10-31)

`ps4_pkg::inner_image::{Entry, InnerImage}` now generates actual unsigned clear D32
PFS bytes, optionally wrapped in raw-block PFSC. This advances the native writer
below the blocked crypto/container layer; **neither output is an installable PKG**.
No passcode, new key constants, signature claims or GP4 build command are involved.

Format evidence is pinned L's `PFS/{PfsStructs,PFSBuilder,FlatPathTable,PFSCWriter}.cs`
at the revision above, inspected directly from the clean external checkout. Native
code implements the layouts independently; reference code is not linked into Rust.
Profile constants (D32 widths, block size, mode/read-only bits, internal flags,
minimum `0x55` blocks and PFSC unknown field 6) come from those named definitions,
not additional crypto material. Reference reader and independent Python structural
checks both passed on native-generated images, not merely upstream-generated PKGs.

Implemented behavior:

* Checked deterministic allocation, inode-block rollover (390 D32 inodes/block),
  contiguous extents, four explicit Unix timestamps, zero padding, super-root,
  `uroot`, empty files/directories and multi-block directories/flat-path tables.
* Slash-prefixed ASCII-uppercase wrapping hash, unsigned hash order, directory bit,
  collision bit/offset and full-path resolver dirents with 24-byte terminators.
  Directory records never cross blocks or leave a truncated dirent-header tail.
* PFSC `0x400` N+1 offset table, checked 64-KiB-aligned data start, streamed raw
  blocks. Table memory does not grow with payload length; no DEFLATE generation.
* At most 32,768 input paths, 60 components, 4096 path bytes and portable ASCII
  components <=255 bytes. Exact declared parents required; duplicate/case/type
  collisions and D32 block overflow refused before I/O. Colliding full paths must
  fit the 255-byte resolver-name profile; longer collisions fail, not truncate.
* One 64-KiB payload buffer; callback receives original input index, file-relative
  offset and exact bounded slice to fill. Metadata RAM scales with capped paths/
  dirents, not payload bytes. Callback errors/short-source errors and short output
  writes propagate. Callback contract requires stable source bytes; this layer
  opens no source path and does not implement a source snapshot or GP4 resource split.
* `write` streams at current output position and leaves partial bytes on error;
  caller must discard them. `write_new` creates owner-only scratch beside destination,
  syncs then hard-links without replacing existing files/symlinks/aliases, including
  destinations created mid-write. Only `.pfs`/`.pfsc` names accepted. Cancellation
  before/between blocks, around callbacks and before publication; unpublished scratch
  removed best-effort. Existing parents required; symlink parents refused. Like GP4
  publication, destination parents must stay stable: no hostile-mutation sandbox.
  Disk requirement is exactly one final image plus filesystem overhead; size queries
  available before writing, no extra payload tree or second image scratch needed.

Executed synthetic reference checks: clear and wrapped images each have **9,002
files / 3 directories**, including known `A~`/`B_` hash collision, empty entries,
9000 sibling files, inode rollover, multi-block lookup/directory and a `13*65536+1`
byte patterned file. Pinned L independently reads both namespaces and payloads;
Python independently checks header/inodes, non-overlapping extents, padding,
namespace, all bytes, lookup order, resolver values and detects lookup/payload
mutations. Rust tests additionally cover path/size refusal, ordering, PFSC corruption,
short writes/source failure, cancellation, scratch cleanup, no-overwrite/race and
symlink output refusal. A >4-GiB layout and multi-block PFSC index are tested with
prefix-only output, **not** a real >4-GiB payload/readback or performance result.
Reproduction: [reference instructions][tests]. No all-block authentication is implied:
this image is intentionally unsigned and has no integrity hashes of its own.

Remaining GP4-to-installable-PKG work: semantic resource validation/placement and
stable source snapshots; explicit new-homebrew keystone policy; reviewed numeric
crypto-input distribution; independent signing/encryption/derivation vectors;
signed/encrypted outer PFS and hash dependencies; licenses, PlayGo and container
records/finalization; completed-output validation; real large-file, independent
full-package and installation/launch/save tests. Base only; updates/remarry unchanged.

## 6. Smallest implementation sequence and exit status

1. **Implemented: minimal `psf::serialize(&Sfo)` with synthetic tests**, no PKG writer/CLI changes.
   Serialize checked SFO 1.1 header/index/key/data tables, aligned offsets, terminators
   and retained formats/capacities/padding; retain unknown keys/types and u32 integer
   bit patterns. Parse/write/reparse fixtures including unknown formats, empty/binary
   values, capacity/offset limits and malformed inputs. Untouched source SFO bytes
   must be retained by callers for operations requiring exact preservation.
   Serialization accepts version 1.1 only, requires raw/typed value consistency,
   enforces parser resource limits and u16 key offsets, and normalizes four-byte
   table/value alignment. No automatic authoring/PUBTOOL edits. Independent writer
   reference and console validation have not been run for this API.
2. **Implemented for standalone apps:** validated GP4 model/import/export/directory generation for the narrow
   subset. Test escaping, relative resolution, duplicates, unsupported settings,
   XML resource limits and source safety; independently load generated base XML.
   Extend to patch XML only after pinning its base-reference encoding and an
   independent round-trip oracle; patch builds stay unsupported until binding works.
3. **Implemented: authoring-only bounded package metadata inventory/preflight**,
   including NP records, original keystone and full raw header/general digests.
   `Game` application mapping, extraction and ZAR behavior remain unchanged;
   synthetic record/key-index refusal tests pass. This is not complete semantic
   rebuild validation; independent package-source comparisons remain unexecuted.
4. Synthetic base-build/structural oracle is now executed. **Clear D32/raw-PFSC
   image layer is implemented and independently checked** as detailed below; it
    requires no new cryptographic inputs. Signed/encrypted S32 generation and its
    independent HMAC/XTS/all-reference evidence are now implemented above; numeric-input
    provenance and remaining crypto/container finalization gates remain unresolved.
   Use bounded buffers/disk scratch and atomic no-overwrite publication as planned.
5. Resolve selected-base binding with independent full-update evidence **before**
   native update writing. Then directory/GP4 full updates, then package-source remarry
   through that same pipeline. Require payload/resource/console gates per stage.
6. CLI first, GTK after acceptance. Merge remains deferred; no changes to existing
   `pack`, extraction, or separate base/update ZAR conversion.

**Stage 1 exit: partial, explicitly blocked.** Supported candidate base profile,
ownership and missing-input inventory are recorded. A small synthetic base oracle
is executed. Exact update binding, complete integrity/provenance evidence, complete
NP requirements and console gates are unresolved; there
is no honest claim that pinned tools can already build/read the intended full-update
profile. Safe SFO/GP4 work can proceed without inventing those missing facts.

[L]: https://github.com/maxton/LibOrbisPkg/tree/643477263b2644e0803e0f58b8726ea4e3f3b7d4
[F]: https://github.com/flatz/pkg_pfs_tool/tree/4e74afa98b0f57b2b50a2182c1ef89905dc040a7
[O]: https://github.com/OpenOrbis/LibOrbisPkg/tree/92a4e7f8e5914cb06b52ba3ae6b0675da438a051
[tests]: ../tests/reference/README.md
