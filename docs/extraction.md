# Milestone 3: PS4 extraction contract

Implemented and checked on Linux, 2026-10-13. This document supersedes the
crypto/layout hypotheses in the original milestone 1 research.

## Verified scope

Two private GD fixtures (base and full update) recover through the public fake
RSA keysets. Both have encrypted signed outer S32 PFS, unsigned inner D32 PFS,
64 KiB filesystem/PFSC blocks, and the package new-crypt flag set. Reference
comparison covers every application file, empty directory, size and SHA-256:

| Fixture | Files | Directories | Decoded file bytes |
| --- | ---: | ---: | ---: |
| Base | 2,735 | 632 | 883,526,661 |
| Full update | 1,848 | 851 | 747,688,709 |

Private manifests and comparisons: `pkgs/reference-extraction/`; original
fingerprints: `pkgs/inventory.json`. The inputs were not modified. Reproduction
is documented in [the reference adapter](../tests/reference/README.md).

Synthetic coverage additionally exercises signed direct/single/double-indirect
mapping, >4 GiB logical files and physical offsets, encrypted metadata tails,
empty files, cross-block seeks and malformed inputs. These are not real-package
variant claims. No >4 GiB real file, data DLC, emulator, Windows or macOS run was
available. DLC is inspection-only until a reference fixture establishes its
extraction contract. Normal/passcode-era inputs have synthetic coverage; no
separate real normal-crypt package was supplied.

## Crypto corrections established during implementation

Primary additional reference: flatz/pkg_pfs_tool revision
[`4e74afa98b0f57b2b50a2182c1ef89905dc040a7`](https://github.com/flatz/pkg_pfs_tool/tree/4e74afa98b0f57b2b50a2182c1ef89905dc040a7).
This is a source reference, not a linked dependency or a claimed executed oracle.
Its `src/keymgr.c`, `src/pkg.c`, `src/pfs.c`, `src/pfs.h` and `src/crypto.c`
resolve the following discrepancies with the original LibOrbisPkg notes:

1. **Recovered IMAGE_KEY is ready for PFS derivation.** The new-crypt
   `HMAC(passcode-derived key, seed)` transform happens before wrapping the image
   key. `keymgr_generate_keys_for_title_keyset` applies it only when starting
   from a passcode; it uses an existing image key directly. Applying it again
   because of the package flag produces invalid plaintext on both local fixtures.
   Similarly, `CheckEkpfs`'s entry-key digest 1 checks the passcode-derived key,
   not necessarily the recovered image key. Both real fixtures fail that check
   but pass outer PFS header HMAC and full reference extraction. DK3's digest
   remains mandatory. No heuristic alternate-key fallback is used.
2. **Header HMAC checks the recovered key/seed.** Derive signing key with
   `HMAC-SHA256(image_key, LE32(2) || seed16)`. HMAC a 0x5a0-byte zero buffer
   containing header bytes 0..0x380, compare with bytes 0x380..0x3a0. Encryption
   uses index 1; first half is tweak key, second half data key. XTS sectors are
   4096 bytes; leave filesystem block zero clear and use image-relative sector
   numbers. No signature-bearing inode/data-block authentication is claimed.
3. **Unaligned container entries are not padded CBC storage.** The routine
   named `aes_decrypt_cbc_cts` actually processes full blocks with CBC and the
   final 1..15 bytes with CFB: XOR with AES-encrypted previous ciphertext block
   (or IV when the entire entry is short). Stored length equals declared length.
   New entry encryption (`flags1 & 0x10000000`) and keys other than index 3 are
   unsupported. An independent OpenSSL-based CBC/CFB-tail vector exercises
   every subrange of a 37-byte entry without any trailing storage. The unaligned
   encrypted entries seen in real fixtures are container artifacts excluded
   from the application tree; encrypted application resources have synthetic
   rather than real-fixture coverage.
4. **PFSC blocks contain zlib frames.** Rust validates stream end, complete input
   consumption, exact logical block length and Adler checksum. Raw blocks are
   identified by stored size equal to logical block size. Empty/oversized stored
   blocks and partial logical final blocks are rejected, not filled with zeros.

Two RSA key pairs are encoded as public mathematical constants (primes only)
in `crypto.rs`; RustCrypto derives the remaining key parameters. Provenance:
`RSAKeyset.PkgDerivedKey3Keyset` and `RSAKeyset.FakeKeyset` in pinned LibOrbisPkg
`Util/Keys.cs`, revision `643477263b2644e0803e0f58b8726ea4e3f3b7d4` (upstream
LGPLv3, [license](https://github.com/maxton/LibOrbisPkg/blob/643477263b2644e0803e0f58b8726ea4e3f3b7d4/LICENSE.txt)).
Only the necessary numeric format inputs are included, not upstream crypto,
parsing or extraction implementations. No private user-key interface is exposed.
RSA failure reports “unsupported keyset or damaged key material”; it cannot
reliably distinguish retail encryption from corrupted fake ciphertext.

## Application tree and rejection policy

Strip both PFS wrappers and inner `uroot`. Include regular files and directories
at application root. Reconstruct named application records under `sce_sys/`:

- IDs `0x1000..0x100e`: SFO, PlayGo, pronunciation, picture, publication/share/save
  resources and `app/` PlayGo resources.
- Icons, pictures, sound, changeinfo and localized resources in the recognized
  `0x1200..0x12df` ranges; trophy `0x1400..0x1463`; recognized keymap entries
  `0x1600..0x17f9`. Gaps are not guessed. The explicit map is `metadata_name`.
- Preserve SFO bytes, runtime PlayGo resources and other listed files. Do not
  apply GP4 rebuild-time SFO edits or drop runtime PlayGo files merely because
  a package builder can regenerate them.
- Exclude IDs below `0x1000`: keys, container digests, license artifacts,
  reserved/image/container information. Unknown application IDs are rejected
  during extraction; inspection still exposes all records.

Files with the same application path from both sources are rejected even if
their contents might be identical. Exact directory duplicates from metadata
parent reconstruction are coalesced; actual repeated directory names, inode
directory aliases/cycles, file/directory conflicts and ASCII-case collisions are
rejected. ASCII-only paths avoid unresolved Unicode normalization/case-fold
rules. Reject separators within components, absolute/traversal paths, control
characters, DOS device names, trailing spaces/dots and other Windows-invalid
characters. Names are not sanitized or silently renamed.

Other rejected shapes: non-GD/delta packages, non-nested images, 64-bit/unknown
PFS modes, non-64-KiB PFS blocks, symlinks/special nodes, fragmented unsigned
files, triple indirection and individually compressed inner files. PFSC block
sizes 4..64 KiB (powers of two) are parsed, but only 64 KiB has real evidence.

## I/O, safety and memory

`Package::open_game()` enumerates first; path/namespace errors occur before
output creation. Entries retain inode mappings, not payloads or complete block
indexes. `Game::read_entry(index)` borrows the game and implements `Read + Seek`
within file bounds. One reader at a time; I/O failures stay observable to callers.

PFSC validates its entire offset map in 8 KiB batches and retrieves offset pairs
on demand. Each PFS layer has a 64 KiB cache; PFSC uses two bounded block buffers.
Container decryption and copying use fixed buffers. Directory/tree metadata is
separate: one million inodes/entries maximum, 64 MiB total stored path bytes,
64 MiB per directory's encoded data, 4,096-byte paths, depth 128, 255-byte names.
These are resource policies, not format maxima; memory scales with the bounded
tree rather than total file bytes or PFSC chunk count.

Measured Linux release extraction of the base fixture, warm cache: **10.820 s**,
**16,768 KiB child peak RSS** via `resource.getrusage(RUSAGE_CHILDREN)`, writing
883,526,661 file bytes. The measured output also passed full reference hashes.
Private measurement: `pkgs/reference-extraction/memory-base.json`. This is one
local extraction observation, not a large-game conversion benchmark or a claim
that total memory is independent of directory count.

Unix extraction uses `rustix` safe descriptor-relative `openat`/`mkdirat`:
`O_NOFOLLOW` for each ancestor and child; `O_CREAT|O_EXCL` for files. It creates a
new owner-only root and never follows existing output symlinks or merges with an
existing tree. Parent directories must exist. Root is marked
`.pkg-tools-incomplete` until all entries are written; I/O errors include the
partial destination. Interrupted trees remain explicitly incomplete; no resume
or rollback is attempted. This is not an atomic publication or power-loss
durability guarantee. Sources are opened read-only; file modes/timestamps are
not restored. Non-Unix disk extraction returns Unsupported rather than falling
back to racy path checks; the streaming library remains portable.
