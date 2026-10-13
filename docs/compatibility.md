# Compatibility targets and format research

Research date: 2026-10-13. This records the original milestone 1 targets and
source observations. Milestone 3 now verifies extraction of two local GD
base/full-update fixtures against adapted pinned LibOrbisPkg; no archive or
emulator run yet. **Implementation corrections and actual support take priority:**
[extraction contract](extraction.md), especially recovered image-key derivation,
CBC/CFB tails and the .NET 8 oracle adaptation. “Target” below means proposed
scope, not blanket support. See [executed comparisons](../tests/reference/README.md)
and [dependencies](dependencies-and-fixtures.md).

## 1. Reproducible reference baseline

These repositories were shallow-cloned and their actual source inspected. Full commits, rather than moving branches or release labels, are the compatibility baseline.

| Reference | Exact investigated commit | Role |
| --- | --- | --- |
| [shadps4-emu/shadPS4][S] | `23c41333822fe8eca4c609b43119180af63ae4ac` | Consumer/layout target: **0.19.1 WIP**, as declared in `CMakeLists.txt`; not a claim that this is a stable 0.19.1 release. |
| [Exzap/ZArchive][Z] | `965b66c8d67b6b7e30fd63b3b75aa91a99ff303b` | Native writer format and independent reader oracle. |
| [maxton/LibOrbisPkg][L] | `643477263b2644e0803e0f58b8726ea4e3f3b7d4` | PS4 container, fake-key recovery, PFS/PFSC and extraction reference. |
| [RPCS3/rpcs3][R] | `6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4` | PS3 package variants, container crypto, PSF parser. |
| [bucanero/pkgi-ps3][P] | `c24a539159a8a1f5209333e50cce03852e5a087f` | Investigated candidate; download/install-task flow, not the selected extraction oracle. |

shadPS4's `externals/zarchive` gitlink at the above commit is **also `965b66c8d67b6b7e30fd63b3b75aa91a99ff303b`**. Its `.gitmodules` points to `shadexternals/ZArchive`; the checked-out gitlink equals the investigated Exzap commit. Pin both consumer and library: a system-library build can instead resolve ZArchive through `find_package`. Sources: [version and build declaration][S-build], [submodule configuration][S-modules], [pinned externals tree/gitlink][S-externals]. Local investigation copies are under `/tmp/opencode/pkg-references/{shadPS4,ZArchive,LibOrbisPkg,rpcs3,pkgi-ps3}`; they are research scratch space, not project dependencies.

## 2. Proposed MVP support matrix

Reference licensing: the pinned top-level license files contain GPLv2 for
[shadPS4](https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/LICENSE),
[RPCS3](https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/LICENSE) and
[pkgi-ps3](https://github.com/bucanero/pkgi-ps3/blob/c24a539159a8a1f5209333e50cce03852e5a087f/LICENSE),
LGPLv3 for [LibOrbisPkg](https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LICENSE.txt),
and MIT-0 for [ZArchive](https://github.com/Exzap/ZArchive/blob/965b66c8d67b6b7e30fd63b3b75aa91a99ff303b/LICENSE).
Use these as format/oracle references under the plan's independent-implementation
policy. Any later source reuse needs its own file-level license review.

Verified exceptions to the target-only matrix below: PS4 header/container-table,
SFO 1.1 and complete application extraction match two local GD base/full-update
fixtures. Both recover fake keys, pass outer PFS header HMAC and use S32 encrypted
outer/D32 clear inner PFS. Other variants still need fixture evidence; DLC is not
implemented for extraction. Header-only inspection still does not establish
FPKG identity. See the current contract for synthetic-only coverage and limits.

| Input / operation | Proposed target | Explicit boundary / source rationale |
| --- | --- | --- |
| PSF/SFO 1.1 (`0x101`) | Read typed values and retain unknown keys/type bytes | Shared baseline in RPCS3 and shadPS4. Unknown-type retention is our policy, not their behavior. [R-psf], [S-psf] |
| PSF/SFO 1.0 (`0x100`) | Read as a separate target variant | Accepted by shadPS4; RPCS3 loader requires 1.1. [S-psf], [R-psf] |
| PS4 FPKG base application | Inspect, extract, convert one package to one base ZAR | GD content with supported fake-key recovery and supported nested PFS/PFSC shape. [L-pkg], [L-pfs], [L-extract] |
| PS4 full/non-delta FPKG update | Inspect, extract, convert to separate sibling update ZAR | No package merge or delta reconstruction; base must exist for a usable overlay. [L-enums], [S-fs] |
| PS4 data-bearing FPKG DLC | Inspect, extract, convert to separate DLC ZAR | Require `CATEGORY` beginning `ac`, valid `CONTENT_ID`, supported payload shape; install under configured add-on root/title ID. Themes are not included merely because AC content type is shared. [L-enums], [S-dlc] |
| PS4 license-only DLC (AL), themes, delta patches (DP/delta flags) | Header/metadata inspection only; conversion rejected | License-only entitlement discovery uses external license files; delta application not established. [L-enums], [S-dlc] |
| PS4 retail or other keysets | Header/available metadata inspection only | Fake-key recovery is deliberately specific; retail extraction is outside project scope. [L-pkg], [L-entry] |
| PFS layout subset | Version 1, magic 20130315, 64 KiB blocks, D32/S32 inode layouts; contiguous data and S32 direct/single-/double-indirect block mapping | Target both normal and new-crypt key derivation. Reject 64-bit inode mode, unsupported block sizes, further indirection, unknown/special node kinds and layouts whose semantics are not established. [L-struct], [L-pfs], [L-crypto] |
| PFSC | Standard indexed compressed/raw blocks wrapping the inner PFS | Validate complete block map and decompressed lengths. Unexplained oversized-block behavior and separately compressed application-file variants require further evidence before support. [L-pfsc] |
| PS3 release/retail PS3-platform PKG | Inspect, enumerate, extract container plaintext | Release `0x8000`, platform `0x0001`, normal PS3 key; ordinary PS3 file kinds below. Preserve nested protected file contents. [R-header], [R-unpkg] |
| PS3 debug PS3-platform PKG | Inspect, enumerate, extract container plaintext | Release `0x0000`, platform `0x0001`, SHA-1-derived stream. [R-header], [R-unpkg] |
| PS3 IDU release packages | Recognize as possible unsupported variant; defer extraction | RPCS3 retries a distinct IDU key after normal-key entry validation fails; no independent IDU corpus established. [R-unpkg], [R-keys] |
| PSP/Vita/PSM packages or PSP-flagged entries | Reject payload extraction in MVP | Platform `0x0002` and per-entry PSP flags imply distinct key selection; `.pkg` and PS3 hosting do not establish PS3-format coverage. [R-header], [R-unpkg] |
| PS3 split packages, unknown entry types/flags, installation semantics | Defer | MVP requires one complete package and known entries; RPCS3's broader installer behavior is not our extraction contract. [R-unpkg] |
| ZArchive v1 writing | Single-file archive, regular files/directories, 64 KiB chunks, read compatibility with pinned reader | Empty files within nonempty-payload archives included. Entirely zero-payload archives deferred pending reader-compatible policy. [Z-common], [Z-writer], [Z-reader] |

These are engineering scope decisions, not claims that all real packages obey the selected shapes. Promote each row separately only after reference comparisons and, for conversion, consumer checks. Extraction should preserve source bytes after container/PFSC decoding; executable or license decryption is a separate operation.

## 3. PSF / PARAM.SFO

### Binary contract

Magic bytes are `00 50 53 46` (`\0PSF`). The header is 20 bytes: magic, little-endian version, key-table offset, data-table offset and entry count. Each 16-byte index record contains `u16 key_offset`, `u16 format`, `u32 data_length`, `u32 data_max_length`, and `u32 data_offset`; offsets are relative to the corresponding key/data table. The practical format tags interpreted little-endian are `0x0004` binary/array, `0x0204` text, and `0x0404` 32-bit integer. RPCS3 models the integer as unsigned while shadPS4 exposes signed values: preserve its 32-bit bit pattern rather than imposing a domain interpretation. [R-psf], [R-psf-h], [S-psf-h]

Important source-reading trap: shadPS4 declares `param_fmt` using a big-endian wrapper but reads it with `.Raw()` and writes with `.FromRaw()`. Do not conclude the on-disk tag is big-endian from that member declaration. RPCS3's explicit little-endian `def_table_t` is clearer. shadPS4 accepts versions 1.0 and 1.1; RPCS3's loader requires 1.1. [S-psf], [S-psf-h], [R-psf]

Proposed parser contract: validate all arithmetic/ranges, index-table extent, bounded key terminators, `data_length <= data_max_length`, actual data extent and exact integer width. Preserve unknown keys, raw unknown formats and padding/max-length information needed for inspection; avoid enum panics. Treat text decoding separately from byte preservation. These are project requirements; the upstream readers are layout references, not validation code to copy wholesale. In particular, shadPS4's parser directly copies indexed structures and treats an unknown format as unreachable. [S-psf], [R-psf]

## 4. PS4 PKG / FPKG

### 4.1 Container identification and tables

PS4's container magic is `7f 43 4e 54` (`\x7fCNT`), distinct from PS3's `\x7fPKG`. LibOrbisPkg reads the PS4 header big-endian. Relevant offsets: entry count `0x10`, entry-table offset `0x18`, body offset/size `0x20/0x28`, 48-byte content-ID field `0x40`, DRM/content type/flags `0x70/0x74/0x78`, PFS flags `0x408`, PFS offset/size `0x410/0x418`, package size `0x430`. Header digests/signature also exist; parsing or decrypting does not itself authenticate them. [L-pkg], [L-reader], [R-header]

A package table record is 32 bytes: six big-endian 32-bit fields (`id`, name-table offset, flags1, flags2, data offset, data size) and eight padding bytes. Encryption flag is `flags1 & 0x80000000`; key index is `(flags2 & 0xF000) >> 12`. Important IDs: entry keys `0x10`, image key `0x20`, names `0x200`, PARAM.SFO `0x1000`, icon0 `0x1200`. Container records and PFS file entries are different namespaces. [L-entry], [L-enums]

Do not label a package “FPKG” from filename, content type, or a supposed universal header bit. The inspected reference's useful operational discriminator is successful fake-key recovery, followed by key/PFS structural checks. `GetEkpfs()` explicitly supports fake packages and returns null for all exceptions, so its failure alone cannot distinguish retail encryption, unavailable material and corruption. Our API should distinguish those outcomes where evidence permits. `CheckEkpfs()` compares the derived-key digest (`SHA256(key) XOR key`) against entry-key record 1. [L-pkg]

GD `0x1A` includes applications/patches/remasters; AC `0x1B` includes data DLC and themes; AL `0x1C` is no-data additional content; DP `0x1E` is delta patch. Patch bits include FIRST_PATCH, SUBSEQUENT_PATCH, DELTA_PATCH and CUMULATIVE_PATCH. Thus content type alone is insufficient to select base/update/DLC behavior: examine flags and SFO together, reject contradictory/unsupported combinations. [L-enums]

### 4.2 Fake-package crypto chain

The selected reference recovery route requires the two fixed RSA keysets named `PkgDerivedKey3Keyset` and `FakeKeyset` in `Util/Keys.cs`; they are concrete format inputs whose provenance/distribution decision must accompany implementation. No game-specific passcode is used by `GetEkpfs()`. Its exact chain is: [L-pkg], [L-rsa], [L-crypto]

1. RSA-2048 decrypt `EntryKeys.Keys[3].key` with `PkgDerivedKey3Keyset` to obtain derived key 3 (`dk3`). `RSA2048Decrypt` calls .NET RSA decrypt with `false` OAEP flag: PKCS#1 v1.5 encryption padding, not OAEP or an RSA signature operation. [L-pkg], [L-crypto]
2. Compute `iv_key = SHA256(serialized_32_byte_image_key_table_record || dk3)`. First 16 bytes are IV; last 16 are AES key. AES-128-CBC-decrypt the image-key bytes, no padding removal. Despite its name `AesCbcCfb128Decrypt`, the inspected helper actually configures CBC, not CFB. [L-pkg], [L-entry], [L-crypto]
3. RSA-2048/PKCS#1-v1.5-decrypt that result using `FakeKeyset`; result is EKPFS. Other encrypted table entries use the same record-hash/CBC construction; the no-passcode entry helper supports **only key index 3**. Reject other encrypted required entries instead of feeding them dk3. [L-pkg], [L-entry], [L-crypto]
4. PFS key material is `HMAC-SHA256(recovered_image_key, LE32(1) || seed16)`.
   Split bytes 0..16 into the tweak key and 16..32 into the data key. **Milestone 3
   correction:** LibOrbisPkg's additional new-crypt seed transform applies when
   starting from a passcode-derived key, not an already-unwrapped image key.
   Applying it again fails both supplied fixtures. Entry-key digest 1 likewise
   need not match the recovered image key. Rust checks DK3's digest and the
   outer PFS header HMAC (signing derivation index 2) instead. Details and the
   resolving flatz reference: [extraction contract](extraction.md). [L-crypto], [L-pfs]
5. Decrypt PFS data with AES-XTS using two 128-bit keys, **4096-byte crypto sectors**. Encryption starts at `PFS block_size / 4096`; the first filesystem block is left clear. Tweak input is the sector's index relative to the PFS image encoded LE64 plus eight zeros, not the package offset and not an index reset at the encrypted region. PFS blocks and XTS sectors are different sizes. [L-pfs], [L-xts]

LibOrbisPkg also has a passcode route: `SHA256(SHA256(BE32(index)) || SHA256(content_id_padded_to_48_bytes) || passcode32)`, with index 1 yielding EKPFS. This is a separate capability, not evidence that every FPKG has an all-zero passcode. Proposed MVP uses fake-key recovery; a user-supplied passcode interface is not needed to establish that target. [L-crypto], [L-pkg]

### 4.3 PFS traversal and PFSC

The actual reference extraction stack is:

```text
PKG region [pfs_image_offset, pfs_image_size]
  -> outer PFS (decrypt sectors when Encrypted mode is set)
  -> outer super-root inode 0 / uroot / pfs_image.dat
  -> PFSC indexed decompression
  -> inner PFS super-root inode 0 / uroot
  -> application relative paths
```

This is explicitly how `PkgTool` and `Gp4Creator` instantiate their readers; it is not a single AES-decrypted flat file table. [L-extract], [L-gp4]

PFS superblock fields are little-endian, version 1 and magic decimal 20130315, with seed at `0x370`. Mode bits include signed `1`, 64-bit `2`, encrypted `4`. The reader chooses signed S32 (`0x2C8` bytes) or unsigned D32 (`0xA8` bytes) inodes, loads inode blocks beginning at one filesystem block, starts traversal at inode 0 and requires `uroot`. It does **not** branch on the 64-bit mode bit despite structure declarations for 64-bit inodes: those declarations are not verified 64-bit traversal support. [L-struct], [L-pfs]

Directory entries refer to inode numbers and carry type, name and record size; the reader skips dot/dotdot. File mapping supports contiguous extents, 12 direct block references and signed single-/double-indirect tables. Signed references occupy 36 bytes (32-byte signature plus 32-bit block number), giving `block_size / 36` references per indirect block. The reader's noncontiguous data view hardcodes `0x10000` block size. Therefore MVP should explicitly validate 64 KiB block size, checked inode/block references, directory cycles, valid record sizes and complete block coverage rather than inheriting silent unknown-node skipping or expanding support from structure names. [L-pfs], [L-struct]

PFSC has a `0x30`-byte header, `PFSC` magic, block size fields, block-offset-table location, data-start field and decompressed length. Adjacent 64-bit offsets determine stored sector sizes. A stored size equal to logical block size is copied raw; a smaller sector is decompressed after skipping two bytes with `DeflateStream`—evidence of zlib-framed DEFLATE use, **not Zstandard**. Confirm header/checksum handling against real blocks before implementation. The reference's `stored_size > block_size` branch emits zeros; its intended sparse/corruption semantics are not established here and should not be copied as general acceptance. [L-pfsc]

The reference also compares inode `Size` and `SizeCompressed` when optionally decompressing individual files. Naming alone does not establish the logical-size rule for every variant. MVP must reject unexplained per-file compression/size combinations until reference hashes establish the expected bytes. No complete signed-PFS hash-validation contract was demonstrated: `PfsReader` consumes signature-bearing layouts but does not authenticate every traversed block. [L-pfs], [L-struct]

### 4.4 Extraction layout: two sources, one application tree

`PkgTool pkg_extract` only walks the inner PFS. That alone is insufficient as the definition of an emulator-ready tree: LibOrbisPkg's builder deliberately removes recognized `sce_sys` files from the inner PFS and puts them in container entries. `Gp4Creator` reconstructs named entries under `sce_sys/`, including names with nested paths, then adds inner PFS files with `/uroot/` stripped. [L-extract], [L-builder], [L-gp4], [L-enums]

Proposed extraction/conversion contract:

- Put inner `uroot` children directly at output root; omit `uroot`, `pfs_image.dat`, package headers and key tables from the application namespace.
- Restore recognized application metadata to `sce_sys/<entry-name>`, particularly byte-preserved `param.sfo`, icons and other named resources; apply declared entry decryption where required. Keep unknown container entries inspectable; do not invent output filenames for them.
- Preserve SFO bytes. `Gp4Creator` edits `PUBTOOLVER`/`PUBTOOLINFO` for rebuild projects; those edits are not appropriate for our byte-preserving converter.
- Fail on conflicting PFS/container paths unless an explicit identical-byte duplicate policy is selected. Establish the exact application metadata inclusion list before extraction completion; generated crypto/container artifacts are not automatically application files.

These are proposed policies derived from the two-source layout, not a claim that `Gp4Creator` performs all of them: its entry extraction copies bytes and omits its own `GeneratedEntries` set. A runtime-complete metadata map and encrypted-entry treatment remain validation work. [L-gp4], [L-builder], [L-entry]

## 5. Exact shadPS4 archive and discovery contract

### 5.1 Archive root and launching

The archive root itself is mounted read-only at `/app0` and `/hostapp`. Launching a `.zar` with no inner path selects `eboot.bin`; SFO is opened as `/app0/sce_sys/param.sfo`. Therefore a base archive must have this shape, **without** a wrapping title-ID directory: [S-boot], [S-zfs]

```text
CUSA12345.zar
  eboot.bin
  sce_sys/param.sfo
  sce_sys/icon0.png                 # if supplied by the package
  ... remaining application files
```

The executable can also be addressed through an inner archive path in the launch code. `.zar` is a literal extension check at the runtime backend boundary; emit lowercase `.zar`. The ZArchive backend strips a leading slash before lookup and rejects write/create/append access. [S-boot], [S-fs], [S-zfs]

Two discovery paths matter. `FindGameByID` probes `<search-dir>/<game_id>` and `<search-dir>/<game_id>.zar`, then recurses through directories; archive acceptance there requires readable `sce_sys/param.sfo`. Big-picture scanning walks configured enabled game-install directories, reads SFO for TITLE/TITLE_ID, skips `-UPDATE`/`-patch` candidates and their archive forms, and uses the archive itself as boot path. Consequently `CUSA12345.zar` is the recommended filename for ID-based lookup; arbitrary names may work through direct launch/UI scanning but should not be promised for ID lookup. This investigation covers the pinned in-repo consumer, not separate launchers. [S-path], [S-ui]

### 5.2 Base and update discovery

For mounts at `/app0` and `/hostapp`, `MntPoints::Mount` builds this ordered backend stack:

1. `<base-stem>-mods`, if present.
2. `<base-stem>-UPDATE`, otherwise `<base-stem>-patch`, unless game patches are disabled.
3. Base content.

The stem is the selected host path with `.zar` removed, **not** a name synthesized from SFO TITLE_ID. Each backend probe prefers an existing directory, then an explicit archive, then the path with `.zar` appended. Thus a base `MyGame.zar` pairs with `MyGame-UPDATE.zar`, not automatically `CUSA12345-UPDATE.zar`. `-UPDATE` and `-patch` are alternatives, not two cumulative layers. [S-fs]

Proposed supported combinations, all untested: base ZAR alone; base ZAR plus sibling update ZAR; unpacked base plus sibling update ZAR; base ZAR plus unpacked update. Update archive root uses the same relative namespace as the base, containing update files directly. Missing files fall through to lower backends; overlay lookup order is visible in the mount-stack consumers. Launching an overlay attempts to resolve/rebase to its sibling base. Do not advertise update-only archives as self-contained games. [S-fs], [S-boot]

Use separate outputs rather than merging base/update content in MVP. Do not guess base compatibility or update ordering from filename alone, or treat a DP payload as already-materialized replacement files. The upstream mount algorithm chooses paths; it does not establish that arbitrary independently supplied packages form a valid pair. [S-fs], [L-enums]

### 5.3 Data DLC and license-only DLC

The add-on root is `EmulatorSettings.GetAddonInstallDir()`, defaulting to `<user-dir>/addcont`. During `sceAppContentInitialize`, the emulator reads the running game's SFO `TITLE_ID`, enumerates immediate children of `<addon-root>/<TITLE_ID>`, accepts directories or `.zar` candidates, and opens `sce_sys/param.sfo` at each child's own root. It extracts the entitlement label from `CONTENT_ID.substr(20)`. The child's filename is not used as the entitlement identifier. [S-settings], [S-dlc], [S-dlc-h]

Recommended layout:

```text
<game-install-dir>/CUSA12345.zar
<game-install-dir>/CUSA12345-UPDATE.zar
<addon-root>/CUSA12345/<entitlement-label>.zar
  sce_sys/param.sfo
  ... DLC payload relative paths
```

`sceAppContentAddcontMount` finds the requested entitlement, mounts a matching child at `/addcontN`, requires CATEGORY beginning `ac`, and rechecks the content-ID suffix. Initialization's CATEGORY test is looser (missing CATEGORY is not rejected there), so target the stricter mount requirement. DLC is not nested inside the base archive, not a `/app0` update overlay, and does not require an `eboot.bin`. [S-dlc]

License-only DLC follows a different path: derive `service_id` from the running game's CONTENT_ID through its last `-`, then open `<LicensesDir>/<service_id>.idx` and `.rif`, using `RIF::GetLicenseOnlyEntitlements()`. A metadata-only DLC ZAR is therefore not an established substitute for license installation. MVP defers AL conversion and license export/import; no title-level entitlement behavior was tested. [S-dlc]

## 6. PS3 PKG variants and extraction boundary

### 6.1 Header and records

PS3-style magic bytes are `7f 50 4b 47`. RPCS3's header separates big-endian release type (`0x8000` release, `0x0000` debug) from big-endian platform (`0x0001` PS3, `0x0002` PSP/Vita). It contains metadata offset/count/size, file count, 64-bit total/data offsets and sizes, a 48-byte ID field, two 64-bit QA-digest words and a 128-bit nonce called `klicensee`. The ordinary PS3 header-area constant is `0xC0`; the extended PSP/Vita layout is a distinct case, not a fixed header size to apply blindly. [R-header]

At decrypted data offset zero is an array of 32-byte big-endian records: name offset/length (32-bit), file offset/length (64-bit), type and padding (32-bit). Name and file offsets address the encrypted-data region, not absolute package byte zero. RPCS3 locates PARAM.SFO through decrypted entries. Metadata inspection and SFO inspection therefore need separate capability/error reporting. [R-header], [R-unpkg]

### 6.2 Crypto variants

**Normal PS3 release:** AES-128 counter stream using the fixed `PKG_AES_KEY` in `Crypto/key_vault.h`. For aligned data-relative offset `o`, encrypt the big-endian 128-bit counter `header.klicensee + floor(o / 16)` with AES-ECB and XOR each 16-byte ciphertext block; increment the counter for subsequent blocks. This is the CTR construction, not CBC. A random-read implementation must align down and discard the leading keystream bytes when the requested offset is unaligned. The latter is a requirement for our I/O API, not a claim that upstream's internal helper accepts arbitrary unaligned offsets. [R-unpkg], [R-keys]

**Debug PS3:** build a 64-byte hash input of eight big-endian 64-bit words `[qa0, qa0, qa1, qa1, 0, 0, 0, block_index]`. SHA-1 it for each 16-byte block, XOR with the first 16 hash bytes; block index is data-relative `offset / 16`. This uses SHA-1 in addition to the SHA-256 needed elsewhere. [R-unpkg]

**Other variants:** RPCS3 tries `PKG_AES_KEY_IDU` if normal-key entry decoding fails; PSP-flagged names/data use `PKG_AES_KEY2`; Vita has further content-type-specific key derivation. These code paths are evidence of distinct variants, not coverage acquired by supporting PS3 retail/debug. Defer IDU and reject platform-2/PSP-flagged entries in MVP. [R-unpkg], [R-keys], [R-header]

### 6.3 Files versus installation

MVP PS3 file-kind allowlist: NPDRM `1`, NPDRM EDAT `2`, regular `3`, folder `4`, SDAT `9`; recognize the overwrite bit `0x80000000` as metadata without automatically overwriting host files. Preserve file payloads after **container** decryption, including nested SELF/EDAT/SDAT. Unknown low-byte kinds (`5`, `6`, additional directory forms) and unknown high flags should be classified unsupported until their semantics are established. These policies are deliberately narrower than RPCS3's installer switch. [R-header], [R-unpkg]

Important oracle difference: RPCS3's installation path performs an additional `DecryptEDAT(..., mode=1, header.klicensee)` step for SDAT entries. Thus hashes of RPCS3-installed SDAT files need not equal hashes of our container-plaintext output. Compare at the agreed container boundary or explicitly exclude that transform from the comparison; do not silently add EDAT decryption to “PKG extraction.” Likewise, installing PS3 files to firmware-specific destinations is separate from preserving package-relative paths in an output directory. [R-unpkg]

`pkgi-ps3` was investigated but not used to infer a desktop package extractor: `source/pkgi_download.c` handles download state/hash and creates queue/install PDB files, with PS3 install orchestration in the project. It is a useful operational reference, while RPCS3 exposes the actual package header/entry and decrypt routines needed here. [P-download], [P-platform]

## 7. ZArchive v1 writer contract

### 7.1 Physical organization and byte order

ZArchive v1 is footer-indexed, not a front-header archive. The pinned writer emits compressed/raw payload, pads the end of that section to an 8-byte boundary, then writes offset records, name table, file tree, empty metadata sections and footer. Numeric serialization uses **big-endian**. Avoid inventing per-file or per-section alignments absent from this writer. [Z-common], [Z-writer]

Footer size is **144 bytes**: six `(u64 offset, u64 size)` pairs in order (compressed data, offset records, names, file tree, metadata directory, metadata data), 32-byte integrity hash, `u64 totalSize`, `u32 version = 0x61bf3a01`, `u32 magic = 0x169f52d6`. These terminal fields are the format identifiers; a `.zar` suffix alone is not format validation. Reader seeks to end minus footer size and validates magic, version, total size and section bounds. [Z-common], [Z-reader]

### 7.2 Payload, indexes and integrity

- All file bytes are concatenated into one logical stream; a new file records its current logical offset, not a fresh compression stream. Chunks are **64 KiB** and may cross file boundaries. The last partial chunk is zero-padded without enlarging the final file's recorded size. [Z-writer]
- Each chunk is independently Zstandard-compressed (upstream writer uses level 6). If compressed size is at least 65536, write raw 65536 bytes instead. Size 65536 is the raw-block marker used by the reader. [Z-writer], [Z-reader]
- Offset records are **40 bytes**: `u64 baseOffset` plus sixteen `u16 storedSizeMinusOne` fields. Each record indexes 16 chunks; reader derives intermediate offsets by summing earlier sizes plus one. The reference writer's compressed-data section begins at zero. [Z-common], [Z-writer], [Z-reader]
- File/directory records are **16 bytes**. First word's high bit marks a file; low 31 bits are the name-table offset. Files have 48-bit logical offset and 48-bit size packed into three words; directories have child-start index, child count and reserved zero. Root is node zero with name offset sentinel `0x7FFFFFFF`. [Z-common], [Z-writer]
- Writer assigns contiguous child ranges breadth-first, sorting each directory's children with the format's ASCII-case-insensitive comparator before serializing. Reader lookup relies on that ordering; do not substitute locale or Unicode collation. [Z-writer], [Z-common], [Z-reader]
- Metadata directory/data are currently emitted with zero size. Integrity is SHA-256 of every output byte including the serialized footer with its hash bytes zeroed; then write the footer with the final digest. The inspected reader's open path does **not** verify that digest. Reader acceptance is therefore insufficient as an integrity-field test. [Z-writer], [Z-reader]

### 7.3 Paths, limits and memory

Name entries have a one-byte length prefix for lengths below 128; otherwise first byte carries low seven bits plus continuation bit, second carries the remaining eight bits. Maximum represented component length is **32767 bytes**. Upstream writer truncates longer names; ours must reject them. Names are `std::string` bytes with no normalization or Unicode validation in this code. ASCII A–Z comparison folds to a–z; `/` and `\` are path separators. Preserve byte-exact supported names, reject NUL/separator ambiguity and case-fold collisions, and document the project's chosen UTF-8 policy instead of claiming upstream guarantees it. [Z-common], [Z-writer]

Enforce the smaller of field and reader limits: 48-bit logical file offsets/sizes, 31-bit name offsets (reserve root sentinel), names section at most `0x7FFFFFFF` bytes, and offset-record/file-tree section sizes at most `0xFFFFFFFF`. Reject arithmetic overflow before narrowing. The pinned reader loads all three index tables in memory; writer also accumulates node/name/chunk-index metadata. Payload streaming is bounded, but **chunk-index memory grows with total payload size** (40 bytes per 1 MiB logical data, plus containers/metadata). A strict payload-size-independent Rust writer needs a spillable offset index or equivalent finalization strategy; do not promise constant total memory merely because compression buffers are 64 KiB. [Z-common], [Z-writer], [Z-reader]

Empty-file nuance: writer can record a zero-length file, but if the entire archive has no payload, it emits no offset records and the pinned reader rejects an empty offset-record table. Proposed initial target permits empty files alongside nonempty payload and rejects a wholly zero-payload input tree until a deliberate reader-compatible encoding is validated. This is a source-observed interoperability edge, not an executed test. [Z-writer], [Z-reader]

## 8. Blockers and decisions before support claims

Historical milestone 1 checklist below. Milestone 3 resolves local base/update
extraction, fixed-key distribution inputs, required dependencies, application
mapping and storage rules; [current remaining gates](extraction.md) supersede
those items. ZArchive, emulator, DLC and broader corpus gates remain open.

1. **Fixture-backed inspection only.** Header/table and plaintext SFO metadata
   match two local candidates. Crypto, decoded layouts, archive readback and
   shadPS4 recognition remain untested. Encrypted records with unaligned declared
   lengths were observed; establish logical versus stored/padded sizes before
   adding decryption-time validation.
2. **PS4 coverage boundaries need real package evidence.** Confirm signed fragmented files through double indirection, new-crypt inputs, compressed/raw PFSC blocks and their checksums, exact `Size`/`SizeCompressed` semantics, and reject unsupported 64-bit/special-node variants. The investigated reader has narrow/hardcoded assumptions and unexplained PFSC branches. [L-pfs], [L-pfsc], [L-struct]
3. **Application metadata reconstruction is mandatory.** Finalize the named container-entry inclusion/decryption map and collision behavior; inner-PFS-only extraction cannot define converter correctness. Do not use GP4 rebuilding's SFO edits as an oracle for byte preservation. [L-builder], [L-gp4], [L-entry]
4. **Fake-key identification is operational, not definitive.** Record missing keys, PKCS#1 decode errors and corrupt PFS separately where possible. Header flags alone have not been established as a universal fake/retail discriminator. Decide how the two fixed upstream RSA keysets enter the project. [L-pkg], [L-rsa]
5. **Consumer checks need three independent combinations.** Base-only recognition/load; base plus full update overlay; base plus data-DLC entitlement discovery/mount. License-only entitlements and delta patches remain excluded. Filesystem recognition, executable loading and actual game runtime behavior are separate results. [S-boot], [S-fs], [S-dlc]
6. **PS3 extraction oracle must agree on payload boundary.** RPCS3 installs can transform SDAT. Normal retail/debug coverage does not include IDU, PSP/Vita or every content type merely because the header can be parsed. [R-unpkg], [R-header]
7. **ZArchive correctness needs more than open success.** Verify footer SHA-256 independently, random reads across shared chunk/file boundaries, sorting and case collisions, empty-file cases and large offsets. Choose explicit zero-payload policy and account for growing chunk indexes. [Z-writer], [Z-reader], [Z-common]

## Pinned source links

Each source link below contains the full investigated revision. Section citations refer to actual source, not README summaries.

[S]: https://github.com/shadps4-emu/shadPS4/tree/23c41333822fe8eca4c609b43119180af63ae4ac
[Z]: https://github.com/Exzap/ZArchive/tree/965b66c8d67b6b7e30fd63b3b75aa91a99ff303b
[L]: https://github.com/maxton/LibOrbisPkg/tree/643477263b2644e0803e0f58b8726ea4e3f3b7d4
[R]: https://github.com/RPCS3/rpcs3/tree/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4
[P]: https://github.com/bucanero/pkgi-ps3/tree/c24a539159a8a1f5209333e50cce03852e5a087f
[S-build]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/CMakeLists.txt#L215-L259
[S-modules]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/.gitmodules
[S-externals]: https://github.com/shadps4-emu/shadPS4/tree/23c41333822fe8eca4c609b43119180af63ae4ac/externals
[S-psf-h]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/core/file_format/psf.h
[S-psf]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/core/file_format/psf.cpp
[S-fs]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/core/file_sys/fs.cpp
[S-zfs]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/core/file_sys/backends/zarchive_fs.cpp
[S-boot]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/emulator.cpp#L294-L398
[S-path]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/common/path_util.cpp#L201-L259
[S-ui]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/imgui/big_picture/big_picture.cpp
[S-settings]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/core/emulator_settings.cpp#L212-L217
[S-dlc]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/core/libraries/app_content/app_content.cpp
[S-dlc-h]: https://github.com/shadps4-emu/shadPS4/blob/23c41333822fe8eca4c609b43119180af63ae4ac/src/core/libraries/app_content/app_content.h#L45
[L-pkg]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/PKG/Pkg.cs
[L-reader]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/PKG/PkgReader.cs
[L-entry]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/PKG/Entry.cs
[L-enums]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/PKG/Enums.cs
[L-rsa]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/Util/Keys.cs
[L-crypto]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/Util/Crypto.cs
[L-pfs]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/PFS/PfsReader.cs
[L-struct]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/PFS/PfsStructs.cs
[L-xts]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/PFS/XtsDecryptReader.cs
[L-pfsc]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/PFS/PFSCReader.cs
[L-extract]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/PkgTool/Program.cs
[L-gp4]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/GP4/Gp4Creator.cs
[L-builder]: https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LibOrbisPkg/PFS/PFSBuilder.cs#L100
[R-header]: https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Crypto/unpkg.h
[R-unpkg]: https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Crypto/unpkg.cpp
[R-keys]: https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Crypto/key_vault.h
[R-psf]: https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Loader/PSF.cpp
[R-psf-h]: https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Loader/PSF.h
[P-download]: https://github.com/bucanero/pkgi-ps3/blob/c24a539159a8a1f5209333e50cce03852e5a087f/source/pkgi_download.c
[P-platform]: https://github.com/bucanero/pkgi-ps3/blob/c24a539159a8a1f5209333e50cce03852e5a087f/source/pkgi_ps3.c
[Z-common]: https://github.com/Exzap/ZArchive/blob/965b66c8d67b6b7e30fd63b3b75aa91a99ff303b/include/zarchive/zarchivecommon.h
[Z-writer]: https://github.com/Exzap/ZArchive/blob/965b66c8d67b6b7e30fd63b3b75aa91a99ff303b/src/zarchivewriter.cpp
[Z-reader]: https://github.com/Exzap/ZArchive/blob/965b66c8d67b6b7e30fd63b3b75aa91a99ff303b/src/zarchivereader.cpp
