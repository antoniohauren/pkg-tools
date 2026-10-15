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
- IDU, PSP/Vita/PSM, split packages and unknown release types are unsupported.
  IDU has no reliable distinct header flag here: an invalid normal-key table
  can mean corruption or an unsupported keyset. The error does not claim to
  distinguish them.
- No package signature, QA digest, or payload authentication. Successful AES
  decoding and structural validation do not establish authenticity. Changes in
  otherwise valid file payloads can pass unnoticed.

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
