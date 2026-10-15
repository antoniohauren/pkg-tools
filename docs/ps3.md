# PS3 PKG inspection and extraction

`ps3-pkg` reads complete PS3-platform (`1`) packages with release type `0x8000`
(normal retail AES-128-CTR) or `0` (debug SHA-1 stream). CLI `inspect` and
`extract`, and the GTK application, detect PS3 by `7f 50 4b 47` magic. GTK shows
SFO metadata/artwork and supports extraction progress/cancellation. ZAR
conversion remains PS4-only and is disabled for PS3 in the GUI.

```sh
cargo run --release -p pkg-cli -- inspect GAME.pkg --json
cargo run --release -p pkg-cli -- extract GAME.pkg NEW_OUTPUT_DIRECTORY
```

The library accepts `Read + Seek` through `Package::open`. It exposes `header`,
raw `metadata`, sorted `entries`, `read_param_sfo`, `read_icon0`, borrowed
`read_entry` (`Read + Seek`), and `extract[_with_cancel|_with_progress]`.
Entries include inferred parents; `header.entry_count` counts original records.
Flags retain the overwrite bit as metadata; extraction never overwrites.

## Supported boundary

- Entry kinds: NPDRM `1`, NPDRM EDAT `2`, regular `3`, directory `4`, SDAT `9`.
  The only accepted high flag is `0x80000000`. Unknown kinds/flags and nonzero
  record padding are rejected before output creation.
- Output preserves package-relative names and container-decrypted bytes.
  `PARAM.SFO`, `ICON0.PNG` and `USRDIR` stay at their original locations;
  no title-ID wrapper or `sce_sys` remapping is added.
- SELF/EDAT/SDAT contents are preserved. RPCS3's installer additionally decrypts
  SDAT and selects installation destinations; those operations are not performed.
- RPCS3 HDD-game boot requires a folder name shorter than 32 bytes. The GUI caps
  generated extraction/liberation folder names accordingly. With CLI extraction,
  choose a short output name such as `NPUB30892`. For existing long-named output,
  rename the game root before booting. SSX direct-folder boot was user-verified
  after this rename with its RAP already installed; this is not a general
  compatibility guarantee for other titles or payload formats.
- IDU, PSP/Vita/PSM, split packages and unknown release types are unsupported.
  IDU has no reliable distinct header flag here: an invalid normal-key table
  can mean corruption or an unsupported keyset. The error does not claim to
  distinguish them.
- No package signature, QA digest, or payload authentication. Successful AES
  decoding and structural validation do not establish authenticity. Changes in
  otherwise valid file payloads can pass unnoticed.

## Liberate

```sh
cargo run --release -p pkg-cli -- liberate GAME.pkg LICENSE.rap Game-rapless.pkg
```

GUI: **Liberate…** opens a source dialog: choose a PKG, the loaded PS3 package,
or an extracted game root containing `PARAM.SFO` and `USRDIR`. The next dialog
shows an automatically matched RAP and offers **Link RAP…** to override it.
Matching uses the full content ID, not the package's display filename or title ID:
`<content-id>.rap`, case-insensitively, beside the source and in its sibling
`exdata` directory; extracted folders also search their root and `exdata` child.
Multiple matches require manual linking. RAP files must contain exactly 16 binary
bytes; cryptographic validation happens during conversion. RAP files have no
embedded content ID, so filename matching alone does not establish a valid license.
No licenses are downloaded. Separate overview links last for the loaded package only.

Extracted folders use `CONTENT_ID` from `PARAM.SFO`, falling back to the NPDRM
header of `USRDIR/EBOOT.BIN`. The folder is read-only. Choose **Folder…** to write
liberated payloads directly into a new `<source>-liberated` folder, or **PKG…** to
save a new `-liberated.pkg`. Both output choices accept either input type.
Folder output preserves the game tree, without creating an intermediate PKG;
existing destinations are refused. Cancellation or I/O failure after creation
leaves an output folder marked `.pkg-tools-incomplete`; remove it before retrying.
Symlinks, special files, incomplete extraction markers and
unsafe/conflicting paths are rejected. Folder inputs must remain unchanged while
conversion runs. Package metadata is synthesized for a free-license PS3 game;
the original container's optional metadata is unavailable after extraction.
RAP files inside the tree are omitted from the output package.

This is an **experimental, entirely native Rust** conversion path intended for
RPCS3 and PS3 CFW/HEN. Neither emulator launch nor console installation/launch
has been executed. It does not produce a Sony-authenticated retail package for
stock firmware. There is no runtime scetool, OpenSSL, Python, or key-file dependency.

Supported conversion boundary:

- PS3 game-executable PKGs (metadata content type `5`), with one matching RAP.
- Local-license NPDRM SELF key revisions `0A`, `19`, `1C`. Metadata is decrypted,
  section HMACs checked, license changed to FREE, NPD hashes regenerated, and
  the header signed using the published 3.55 NPDRM key/loader curve `0x27`.
  Payload sections, compression, executable code, application version, capabilities,
  and required firmware are preserved. Other SELF revisions are explicit errors.
- Local-license common EDAT (type `0`), version `3`/`4`, uncompressed flags
  `0x0C`/`0x3C`, block sizes 1–32 KiB. Header/metadata/block hashes are checked.
  The original developer key must match a known candidate or occur as 16 raw
  bytes in decoded local-license SELF sections. Conversion keeps that key so
  existing game code can open the free-license EDAT; unavailable keys are errors.
  Output uses authenticated, encrypted `0x0C` blocks with regenerated hashes.
- SDAT, already-free EDAT/SELF, non-NPDRM SELF, SFO, artwork, and ordinary files
  are preserved. Files are identified by magic, not just extensions.
- Network licenses, different per-file content IDs/RAPs, compressed EDAT,
  PS2 Classics/disc-bound EDAT, unsupported key revisions and unknown crypto
  modes fail without publishing output. No silent partial liberation.
- Output is a debug PKG with free-license metadata and recomputed debug header,
  metadata, QA and stream-cipher fields. This is not full Sony signature
  authentication; common EDAT signature slots are zeroed and existing SELF
  footer signatures are not regenerated. Modified-environment acceptance still
  needs testing on the target firmware/emulator.

`ps3_pkg::Rap::from_bytes` parses the binary RAP. The library entry point is
`Package::liberate_with_progress(&rap, output, cancelled, progress)`.
The source is read-only. Output must be new; an exclusive sibling scratch
directory holds the new package and is removed on failure/cancellation. Inputs
must remain unchanged during the operation. Successful publication uses a
no-overwrite hard link, including protection against destination creation races.
The destination filesystem must support hard links. A crash can leave the hidden
scratch directory; it contains an unpublished PKG, not a separate plaintext tree.

Limits: each inspected SELF/local EDAT, total transformed files, and total decoded
SELF sections are separately bounded to 256 MiB; SELF headers to 16 MiB. Multiple
bounded buffers can coexist. Unchanged payloads stream in 64 KiB chunks. Output
data regions above 4 GiB are rejected by the legacy package-metadata size field.
Preparation includes integrity checks, developer-key discovery and a QA hashing
pass. Progress starts when writing the prepared package; cancellation is checked
between sections, key-search batches, EDAT blocks and streaming chunks. No
install/launch guarantee follows from successful payload verification.

Verification (2026-10-15): supplied **SSX / NPUB30892** PKG + RAP produced
`pkgs/ps3/SSX-rapless.pkg`. An independent Python/cryptography oracle checked
the converted EBOOT's complete decoded sections, HMACs and new ECDSA signature;
both converted EDATs' complete plaintext, header/metadata/block hashes; and
unchanged files' first/last 64 KiB (whole files up to 128 KiB). It did **not** hash
all 4.17 GB of unchanged data or execute either target runtime. Synthetic tests
cover crypto known answers, EDAT layouts, wrong RAP, damaged/truncated data,
unsupported formats, cancellation, no-overwrite and publication races.

Format references: pinned RPCS3 [`key_vault.h`](https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Crypto/key_vault.h),
[`key_vault.cpp`](https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Crypto/key_vault.cpp),
[`unedat.cpp`](https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Crypto/unedat.cpp);
[scetool's SELF header signing/encryption layout](https://github.com/naehrwert/scetool/blob/d78d8986c9ab831f084516f21ecdf87080ac7b78/sce.cpp); loader curve `0x27` from
[published curve data](https://github.com/Sorvigolova/scetool/blob/64a4689a388c401e5b24bc5c9397111a70d03922/PS3/ldr_curves);
[PSL1GHT's debug PKG layout](https://github.com/ps3dev/PSL1GHT/blob/master/tools/sfo_pkg/pkg.c). Rust implementations are native; reference tools are
not vendored. `num-bigint-dig` handles the custom published signing curve and
`flate2` reads compressed SELF sections; both already existed in the workspace.

## Validation, memory and filesystem rules

Input length must equal the declared size. Header, metadata, encrypted data,
record table, names and payload ranges use checked 64-bit arithmetic. Metadata
records must fit their declared region and have unique IDs. Unknown metadata
values remain available as bytes. Name/payload ranges may not overlap the entry
table. Directories cannot carry file payloads.

Limits: one million original/inferred entries; 64 MiB tree path bytes; 16 MiB
metadata region and SFO; 65,536 metadata records; 4 MiB artwork; 4,096-byte paths,
128 components, 255-byte ASCII components. Trailing NUL name padding is removed;
embedded NULs, traversal, absolute paths, portable filename hazards, duplicate
entries, file/directory conflicts and ASCII-case aliases are rejected. Inferred
directories can be followed by one explicit directory record.

Payload reads use at most 64 KiB per call; unaligned seeks use the absolute
data-region counter position. Memory scales with bounded tree/metadata, not
payload size. Debug hashing is slower than retail AES.

Both PS3 and PS4 use `pkg-fs` for filename policy and Unix descriptor-relative
output creation (`NOFOLLOW`, exclusive creation). Destination must be new, with
existing nonsymlink parents. Failed/cancelled output remains marked
`.pkg-tools-incomplete`, and errors identify its location. Cancellation is
checked before creation and between entries/64 KiB output chunks. Parsing the
initial tree is not interruptible. Non-Unix disk extraction is unsupported;
streaming inspection/readers use portable Rust I/O.

## References and executed checks (2026-10-15)

Format baseline: [RPCS3 `unpkg.h`](https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Crypto/unpkg.h),
[`unpkg.cpp`](https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Crypto/unpkg.cpp),
[`key_vault.h`](https://github.com/RPCS3/rpcs3/blob/6fe3c87fb41c29b21d8796b15eca5c80ad3b36d4/rpcs3/Crypto/key_vault.h).
These are layout/crypto references, not vendored implementations. The normal
PS3 AES key is a fixed format constant from that reference.

- Local retail fixture: **310 files, 22 directories**, all paths, sizes and
  SHA-256 matched the independent Python/OpenSSL oracle. All exposed header
  fields, raw metadata packets and SFO keys/formats/capacities/bytes matched.
  Extracted tree and private manifest: ignored `pkgs/ps3/{extracted,reference.json}`.
- Debug: synthetic-only coverage. Python/hashlib-created fixture exercises CLI
  JSON/human inspection, SFO, extraction, no-overwrite and GUI metadata loading.
- Rust tests cover retail/debug known answers, unaligned seeks, 64 KiB boundaries,
  virtual >4 GiB files/offsets, malformed/truncated/overflowed ranges, unsupported
  flags/platforms, traversal/collisions, symlink destinations, progress,
  cancellation and failed reads leaving marked partial output.
- Workspace tests, formatting and warning-free Clippy passed on Linux. The
  graphical smoke test passed with the supplied PS3 game, including artwork,
  drag-and-drop, dialogs, cancellation controls and disabled ZAR conversion.

The oracle implements the pinned source's container boundary using independent
crypto/parsing. It is **not an executed RPCS3 installer comparison**. Real debug
packages, additional retail titles, emulator launch, and Windows/macOS remain
unverified. [Reproduction](../tests/reference/README.md#ps3-container-plaintext-oracle).
