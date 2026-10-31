//! Legacy FPKG encoding, not general-purpose secure encryption or signing.
use super::invalid;
use aes::{
    Aes128,
    cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding},
};
use rsa::{BigUint, RsaPublicKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256};
use std::io;

const RSA_BYTES: usize = 256;
const MESSAGE_BYTES: usize = 32;
const MESSAGE_START: usize = RSA_BYTES - MESSAGE_BYTES;
const PADDING_END: usize = MESSAGE_START - 1;
const MAX_METADATA: usize = 0x400;

/// Encrypt IMAGE_KEY, license.dat, license.info or supported NP records from an
/// exact final 32-byte BE table record. License.info uses D[2], others D[3].
/// Caller supplies plaintext, not a license generator. Declared size must equal
/// plaintext rounded up to 16 bytes (zero padding, no extra block when aligned).
/// Only legacy CBC, zero reserved words and aligned offsets are supported.
/// Returned ciphertext includes encrypted zero padding; hash its declared length.
/// Moving/reflagging the record requires re-encryption. Inputs are never changed.
/// NP title/binding lengths are fixed at 0xa0/0x214; the latter returns 0x220 CBC
/// bytes including encrypted zero padding, all covered by its stored-byte digest.
pub fn encrypt_metadata(
    final_record: &[u8],
    content_id: &str,
    passcode: &str,
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    let record: &[u8; 32] = final_record
        .try_into()
        .map_err(|_| invalid("metadata record must be exactly 32 bytes"))?;
    let word = |i| u32::from_be_bytes([record[i], record[i + 1], record[i + 2], record[i + 3]]);
    let expected_index = match word(0) {
        0x20 | 0x400 | 0x402 | 0x403 => 3,
        0x401 => 2,
        _ => return Err(invalid("unsupported encrypted metadata ID")),
    };
    if word(8) & 0x8000_0000 == 0
        || word(8) & 0x1000_0000 != 0
        || word(12) != expected_index << 12
        || !word(16).is_multiple_of(16)
        || record[24..] != [0; 8]
    {
        return Err(invalid(
            "unsupported metadata flags, index, offset or reserved words",
        ));
    }
    let size = word(20) as usize;
    let np = matches!(word(0), 0x402 | 0x403);
    if plaintext.is_empty()
        || plaintext.len() > MAX_METADATA
        || size > MAX_METADATA
        || if np {
            plaintext.len() != size
                || size != if word(0) == 0x402 { 0xa0 } else { 0x214 }
                || word(8) != 0x8000_0000
        } else {
            plaintext.len().div_ceil(16) * 16 != size
        }
    {
        return Err(invalid(
            "metadata declared size must match bounded padded plaintext",
        ));
    }
    if !crate::gp4::valid_content_id(content_id)
        || passcode.len() != 32
        || !passcode.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(invalid(
            "metadata requires valid content ID and 32 printable ASCII passcode bytes",
        ));
    }
    let id = content_id
        .as_bytes()
        .try_into()
        .map_err(|_| invalid("content ID length"))?;
    let passcode = passcode
        .as_bytes()
        .try_into()
        .map_err(|_| invalid("passcode length"))?;
    let derived = crate::crypto::derived_key(id, passcode, expected_index);
    let mut hash = Sha256::new();
    hash.update(record);
    hash.update(derived);
    let material = hash.finalize();
    let size = if np { size.next_multiple_of(16) } else { size };
    let mut stored = vec![0; size];
    stored[..plaintext.len()].copy_from_slice(plaintext);
    let full = size / 16 * 16;
    cbc::Encryptor::<Aes128>::new_from_slices(&material[16..], &material[..16])
        .map_err(|_| invalid("AES key/IV length"))?
        .encrypt_padded::<NoPadding>(&mut stored[..full], full)
        .map_err(|_| invalid("unaligned metadata storage"))?;
    Ok(stored)
}

pub(super) fn decrypt_metadata(data: &mut [u8], material: &[u8; 32]) -> io::Result<()> {
    crate::crypto::cbc_decrypt(data, &material[16..], &material[..16])
        .map_err(|_| invalid("invalid source crypto ciphertext"))
}

/// Deterministic legacy type-2 wrapping of exactly 32 bytes with caller-supplied
/// raw 256-byte big-endian RSA-2048 modulus and raw BE exponent 01 00 01.
/// Also encodes the FPKG *fake* header hash; this is PUBLIC exponentiation, never
/// authentic signing. No package moduli, private operations or key recovery.
/// Deterministic padding leaks equality and is not modern secure encryption.
pub fn public_rsa_wrap(
    modulus: &[u8],
    exponent: &[u8],
    message: &[u8],
) -> io::Result<[u8; RSA_BYTES]> {
    if modulus.len() != RSA_BYTES
        || modulus[0] & 0x80 == 0
        || exponent != [1, 0, 1]
        || message.len() != MESSAGE_BYTES
    {
        return Err(invalid(
            "wrapping requires raw RSA-2048 modulus, exponent 65537 and 32-byte message",
        ));
    }
    let key = RsaPublicKey::new(
        BigUint::from_bytes_be(modulus),
        BigUint::from_bytes_be(exponent),
    )
    .map_err(|_| invalid("invalid RSA public key"))?;
    let padded = wrapping_block(modulus, message);
    // Existing maintained bignum primitive; only public exponentiation, no signing.
    let ciphertext = BigUint::from_bytes_be(&padded)
        .modpow(key.e(), key.n())
        .to_bytes_be();
    if ciphertext.len() > RSA_BYTES {
        return Err(invalid("RSA output exceeds modulus width"));
    }
    let mut output = [0; RSA_BYTES];
    output[RSA_BYTES - ciphertext.len()..].copy_from_slice(&ciphertext);
    Ok(output)
}

fn wrapping_block(modulus: &[u8], message: &[u8]) -> [u8; RSA_BYTES] {
    let mut hash = Sha256::new();
    hash.update(modulus);
    hash.update(message);
    let seed = Sha256::digest(hash.finalize());
    let words = std::array::from_fn(|i| {
        u32::from_be_bytes([
            seed[4 * i],
            seed[4 * i + 1],
            seed[4 * i + 2],
            seed[4 * i + 3],
        ])
    });
    let mut mt = Mt::new(&words);
    let mut block = [0; RSA_BYTES];
    block[1] = 2;
    block[MESSAGE_START..].copy_from_slice(message);
    let mut position = 2;
    while position < PADDING_END {
        let mut source = [0; 48];
        for word in source.as_chunks_mut::<4>().0 {
            word.copy_from_slice(&mt.next().to_be_bytes());
        }
        for byte in Sha256::digest(source) {
            if byte != 0 {
                block[position] = byte;
                position += 1;
                if position == PADDING_END {
                    break;
                }
            }
        }
    }
    block
}

// MT19937 init_by_array and tempering, used only by this legacy padding format.
// Algorithm constants are PRNG parameters, not embedded package keys.
const MT_WORDS: usize = 624;
const MT_PERIOD: usize = 397;
const MT_ARRAY_SEED: u32 = 19650218;
const MT_INIT_FACTOR: u32 = 1812433253;
const MT_SEED_MIX_FACTOR: u32 = 1664525;
const MT_FINAL_MIX_FACTOR: u32 = 1566083941;
struct Mt {
    state: [u32; MT_WORDS],
    cursor: usize,
}
impl Mt {
    fn new(seed: &[u32; 8]) -> Self {
        let mut state = [0u32; MT_WORDS];
        state[0] = MT_ARRAY_SEED;
        for i in 1..MT_WORDS {
            state[i] = MT_INIT_FACTOR
                .wrapping_mul(state[i - 1] ^ (state[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        let mut index = 1;
        for step in 0..MT_WORDS {
            state[index] = (state[index]
                ^ (state[index - 1] ^ (state[index - 1] >> 30)).wrapping_mul(MT_SEED_MIX_FACTOR))
            .wrapping_add(seed[step % seed.len()])
            .wrapping_add((step % seed.len()) as u32);
            index += 1;
            if index == MT_WORDS {
                state[0] = state[MT_WORDS - 1];
                index = 1;
            }
        }
        for _ in 1..MT_WORDS {
            state[index] = (state[index]
                ^ (state[index - 1] ^ (state[index - 1] >> 30)).wrapping_mul(MT_FINAL_MIX_FACTOR))
            .wrapping_sub(index as u32);
            index += 1;
            if index == MT_WORDS {
                state[0] = state[MT_WORDS - 1];
                index = 1;
            }
        }
        state[0] = 0x8000_0000;
        Self {
            state,
            cursor: MT_WORDS,
        }
    }
    fn next(&mut self) -> u32 {
        if self.cursor == MT_WORDS {
            for i in 0..MT_WORDS {
                let joined =
                    (self.state[i] & 0x8000_0000) | (self.state[(i + 1) % MT_WORDS] & 0x7fff_ffff);
                self.state[i] = self.state[(i + MT_PERIOD) % MT_WORDS]
                    ^ (joined >> 1)
                    ^ if joined & 1 != 0 { 0x9908_b0df } else { 0 };
            }
            self.cursor = 0;
        }
        let mut word = self.state[self.cursor];
        self.cursor += 1;
        word ^= word >> 11;
        word ^= (word << 7) & 0x9d2c_5680;
        word ^= (word << 15) & 0xefc6_0000;
        word ^ (word >> 18)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "ZZ0000-CUSA00000_00-SYNTHETIC0000000";
    // Public half of original disposable pair; never a package wrapping modulus.
    const MODULUS: &str = concat!(
        "8b458489ad2f98c341e0ddd4fb04ed58ecae5458d0fee4bceec3c9d1cc823d945",
        "6825d80320b93121dae015814792ee8fcf83a46576751d7ac3599b83b80d5781d",
        "5884323905714665d289d3fd4b711ca8a70efd5a85150e5d82c0f69eac48b0ddc",
        "561d0ac05ced75183f0e84eea47addc06cda3aa74a8efa7e8ef3192a2ea7611",
        "57a24f88acb9e9fbc197262eca1b1917420a8408975fe53bde67cc54626c4866d",
        "3529d99c9e72b3c46ac7d6906251163af3f4981a90a961795e4a6ea2c803de6e",
        "47adb7503726fbd9a036da8bfcad3589c892a748df4e6f1f7ac3ac84a4fec1cac",
        "b53ba12ff8b6b74eb14d0c2d799809ed83c01401597ead9ef0b06bbde915"
    );
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), 2 * N);
        std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }
    fn record(id: u32, index: u32, offset: u32, flags: u32, size: u32) -> [u8; 32] {
        let mut result = [0; 32];
        for (word, value) in result.as_chunks_mut::<4>().0.iter_mut().zip([
            id,
            0,
            flags,
            index << 12,
            offset,
            size,
            0,
            0,
        ]) {
            word.copy_from_slice(&value.to_be_bytes());
        }
        result
    }
    fn passcode() -> String {
        (0x21u8..=0x40).map(char::from).collect()
    }

    #[test]
    fn independent_np_binding_padded_cbc_and_relocation() {
        let plain: Vec<u8> = (0..0x214).map(|i| (i % 251) as u8).collect();
        let row = record(0x403, 3, 0x3000, 0x80000000, 0x214);
        let pass = "00000000000000000000000000000000";
        let stored = encrypt_metadata(&row, ID, pass, &plain).unwrap();
        // Independent Python hashlib + cryptography CBC, source-confirmed padding.
        assert_eq!(stored.len(), 0x220);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&stored)),
            hex("3cf195771f9037c3e0398c024856f56e257960d7f65819822c9434511a325f1c")
        );
        for changed in [
            record(0x403, 3, 0x3010, 0x80000000, 0x214),
            record(0x403, 3, 0x3000, 0xc0000000, 0x214),
            record(0x403, 2, 0x3000, 0x80000000, 0x214),
        ] {
            let result = encrypt_metadata(&changed, ID, pass, &plain);
            if changed[16..20] != row[16..20] {
                assert_ne!(result.unwrap(), stored);
            } else {
                assert!(result.is_err());
            }
        }
        assert!(
            encrypt_metadata(
                &record(0x403, 3, 0x3000, 0x80000000, 0x220),
                ID,
                pass,
                &plain
            )
            .is_err()
        );
    }

    #[test]
    fn independent_padding_public_wrapping_and_metadata_vectors() {
        let modulus = hex::<256>(MODULUS);
        let message: [u8; 32] = std::array::from_fn(|i| i as u8);
        let block = wrapping_block(&modulus, &message);
        assert_eq!(&block[..2], &[0, 2]);
        assert!(block[2..223].iter().all(|&b| b != 0));
        assert_eq!(block[223], 0);
        assert_eq!(&block[224..], &message);
        // Independent CPython MT19937 + hashlib + integer pow, not a roundtrip.
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(block)),
            hex("393fc123e6fe2d0f9492d1bf6e6dd31eb8a24cac67f5095b902559d6bdb95601")
        );
        let wrapped = public_rsa_wrap(&modulus, &[1, 0, 1], &message).unwrap();
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(wrapped)),
            hex("992b8f5c359593513c98449cca5b3e991f3b84957943c046d4f24fbb101b9dc3")
        );
        assert_eq!(
            wrapped,
            public_rsa_wrap(&modulus, &[1, 0, 1], &message).unwrap()
        );
        let mut artifact = [modulus.as_slice(), &message, &block, &wrapped].concat();
        for (id, index, offset, flags, expected) in [
            (
                0x401,
                2,
                0x3000,
                0x80000000,
                "722d861292d6b3c8537b018796be501fbc82249dd81afceffab5f677fc9bbd4b",
            ),
            (
                0x400,
                3,
                0x3000,
                0x80000000,
                "4ffef2d448b9419816437c98e14d0166782df28ff63f46979351b5b2114a9ec6",
            ),
            (
                0x400,
                3,
                0x3010,
                0x80000000,
                "cc40bfc92ec920a33e077d9bb6c98c135abd123e5872bd4c98d05493ec84309d",
            ),
            (
                0x400,
                3,
                0x3000,
                0xc0000000,
                "a570efb4aa3164d7d8bf781cc05f0b72a901ef4344a2fabb16ff850eae90ac55",
            ),
        ] {
            let record = record(id, index, offset, flags, 32);
            let plain: Vec<_> = (0..17).collect();
            let encrypted = encrypt_metadata(&record, ID, &passcode(), &plain).unwrap();
            assert_eq!(encrypted, hex::<32>(expected));
            assert_eq!(plain, (0..17).collect::<Vec<_>>());
            let mut padded = plain;
            padded.resize(32, 0);
            // Aligned inputs get no extra padding block.
            assert_eq!(
                encrypt_metadata(&record, ID, &passcode(), &padded).unwrap(),
                encrypted
            );
            artifact.extend_from_slice(&record);
            artifact.extend_from_slice(&padded);
            artifact.extend_from_slice(&encrypted);
            let derived = crate::crypto::derived_key(
                ID.as_bytes().try_into().unwrap(),
                passcode().as_bytes().try_into().unwrap(),
                index,
            );
            let material = Sha256::digest([record.as_slice(), &derived].concat());
            let mut decrypted = encrypted;
            crate::crypto::cbc_decrypt(&mut decrypted, &material[16..], &material[..16]).unwrap();
            assert_eq!(decrypted, padded);
        }
        if let Some(path) = std::env::var_os("PKG_TOOLS_CONTAINER_CRYPTO_OUTPUT") {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap()
                .write_all(&artifact)
                .unwrap();
        }
    }

    #[test]
    fn rejects_malformed_keys_lengths_and_unsupported_metadata_states() {
        let modulus = hex::<256>(MODULUS);
        for length in [0, 31, 33, 256, 257] {
            let message = vec![0; length];
            assert!(public_rsa_wrap(&modulus, &[1, 0, 1], &message).is_err());
        }
        for exponent in [&[][..], &[3], &[0, 1, 0, 1], &[1, 0, 0]] {
            assert!(public_rsa_wrap(&modulus, exponent, &[0; 32]).is_err());
        }
        for key in [
            vec![],
            modulus[..255].to_vec(),
            vec![0; 256],
            vec![0xff; 257],
        ] {
            assert!(public_rsa_wrap(&key, &[1, 0, 1], &[0; 32]).is_err());
        }
        let mut even = modulus;
        even[255] &= 0xfe;
        assert!(public_rsa_wrap(&even, &[1, 0, 1], &[0; 32]).is_err());
        let good = record(0x401, 2, 0x3000, 0x80000000, 32);
        for length in [0, 1, 16, 33, 1025] {
            assert!(encrypt_metadata(&good, ID, &passcode(), &vec![0; length]).is_err());
        }
        for length in [0, 31, 33] {
            assert!(encrypt_metadata(&vec![0; length], ID, &passcode(), &[0; 32]).is_err());
        }
        for index in [0, 1, 3, 4, 15, 16] {
            assert!(
                encrypt_metadata(
                    &record(0x401, index, 0x3000, 0x80000000, 32),
                    ID,
                    &passcode(),
                    &[0; 32]
                )
                .is_err()
            );
        }
        for (id, index, offset, flags, size) in [
            (0x402, 2, 0x3000, 0x80000000, 32),
            (0x20, 2, 0x3000, 0x80000000, 32),
            (0x401, 2, 0x3001, 0x80000000, 32),
            (0x401, 2, 0x3000, 0x90000000, 32),
            (0x401, 2, 0x3000, 0, 32),
            (0x401, 2, 0x3000, 0x80000000, 31),
            (0x401, 2, 0x3000, 0x80000000, u32::MAX),
        ] {
            assert!(
                encrypt_metadata(
                    &record(id, index, offset, flags, size),
                    ID,
                    &passcode(),
                    &[0; 32]
                )
                .is_err()
            );
        }
        let mut reserved = good;
        reserved[31] = 1;
        assert!(encrypt_metadata(&reserved, ID, &passcode(), &[0; 32]).is_err());
        for (id, pass) in [
            ("invalid", passcode()),
            (ID, "short".into()),
            (ID, "\n".repeat(32)),
        ] {
            assert!(encrypt_metadata(&good, id, &pass, &[0; 32]).is_err());
        }
        // Every encrypted record in the actual plan uses the appropriate D[index].
        let plan = super::super::BaseContainerLayout::plan(
            65536,
            &[
                super::super::RecordSize {
                    id: 0x1000,
                    size: 32,
                },
                super::super::RecordSize {
                    id: 0x1003,
                    size: 32,
                },
            ],
        )
        .unwrap();
        for row in plan.entry_table().as_chunks::<32>().0 {
            let id = u32::from_be_bytes(row[..4].try_into().unwrap());
            if matches!(id, 0x20 | 0x400 | 0x401) {
                let size = u32::from_be_bytes(row[20..24].try_into().unwrap()) as usize;
                assert_eq!(
                    encrypt_metadata(row, ID, &passcode(), &vec![0; size])
                        .unwrap()
                        .len(),
                    size
                );
            }
        }
    }
}
