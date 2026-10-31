use crate::{Entry, Error};
use aes::{
    Aes128,
    cipher::{BlockModeDecrypt, KeyInit, KeyIvInit, block_padding::NoPadding},
};
use hmac::{Hmac, Mac};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey};
use sha2::{Digest, Sha256};
use xts_mode::Xts128;

// Public interoperability constants only; provenance: docs/extraction.md.
const FAKE_P: &str = "fef6bf1d69ab16250847556b86e43588722ab13df8b644cab3ab19d10424280a7455b8154509cc131cf2ba37a903908f0210ff257986cc18509a105f5b4c1c4eb0a7e359b12da0c6b0202c213312b3af723483cd522faf0f205a1bc0e2a376340fd7fcc141c9f979401742213e9dfdc7c150de445ac931896a7805be65b4e82d";
const FAKE_Q: &str = "c79e4758007d6282b0d22281d4a8971b790c3ab0d7c930e3c3538e57eff09b9fb39052c6942236aae64a5f721d70e87658c8b291ce9cc3e9097f2e4797cc9039153531de1f0c8c0dc1c292be97bf2f91a18c7d50a8212fd7a29a7eb5a72a9002d9f33dd1ebb8e05a799e7d8dca186dbd9ea180286b2afe51249b6f4d84778023";
const DK3_P: &str = "f967ad9912310c56a22e161c46b34d5b43be42a2f686968042c3c73fc342f58749339f075d6e2c04fde3e1b2ae0a0cf0c7a61ca16350c8099c5124526c5e5ebd1e2706bbbc9e94e135d46db3cb3c68dd68b3fe6ccb8d8220762363b7e96810014edcba275d01c12d805e2baf826bd884b6105286a7898eae9ae289c6f7d587fb";
const DK3_Q: &str = "d7a10f9a8bf2c91195329a8cf0d94047f568a00dbdc1fc432f65f9c3610f257754add758ac8440608d3ff3658975b5c62c511a2f1f22e4431154bec9b4c7b51b050bbc569acd4ad973685e5cfb92b78b0dfff507cab4c89b963c079e3e6b2a11f28ab18ad72e1ba5532406ed50b89067b1e241c69201ee10f061bbfbb27d4a73";

pub(crate) fn rsa_key(fake: bool) -> RsaPrivateKey {
    let (p, q) = if fake {
        (FAKE_P, FAKE_Q)
    } else {
        (DK3_P, DK3_Q)
    };
    let primes =
        [p, q].map(|v| BigUint::parse_bytes(v.as_bytes(), 16).expect("fixed RSA constants"));
    RsaPrivateKey::from_primes(primes.to_vec(), BigUint::from(65537u32)).expect("fixed RSA key")
}

fn unwrap(data: &[u8], fake: bool) -> Result<[u8; 32], Error> {
    rsa_key(fake)
        .decrypt(Pkcs1v15Encrypt, data)
        .map_err(|_| Error::KeyRecoveryFailed)?
        .try_into()
        .map_err(|_| Error::KeyRecoveryFailed)
}

fn check_digest(key: &[u8; 32], expected: &[u8]) -> Result<(), Error> {
    let hash = Sha256::digest(key);
    if hash
        .iter()
        .zip(key)
        .map(|(a, b)| a ^ b)
        .ne(expected.iter().copied())
    {
        return Err(Error::Malformed("recovered key digest mismatch"));
    }
    Ok(())
}

pub(crate) fn recover(
    keys: &[u8; 2048],
    image: &mut [u8; 256],
    entry: &Entry,
) -> Result<([u8; 32], [u8; 32]), Error> {
    let dk3 = recover_dk3(keys)?;
    let material = entry_material(entry, &dk3);
    cbc_decrypt(image, &material[16..], &material[..16])?;
    let ekpfs = unwrap(image, true)?;
    // The wrapped image key may already include the new-crypt seed transform;
    // entry-key digest 1 describes the passcode-derived key, not this image key.
    Ok((dk3, ekpfs))
}

pub(crate) fn recover_dk3(keys: &[u8; 2048]) -> Result<[u8; 32], Error> {
    let dk3 = unwrap(&keys[256 + 3 * 256..256 + 4 * 256], false)?;
    check_digest(&dk3, &keys[32 + 3 * 32..32 + 4 * 32])?;
    Ok(dk3)
}

pub(crate) fn entry_material(entry: &Entry, dk3: &[u8; 32]) -> [u8; 32] {
    let mut record = [0; 32];
    for (i, value) in [
        entry.id,
        entry.name_offset,
        entry.flags1,
        entry.flags2,
        entry.offset,
        entry.size,
    ]
    .iter()
    .enumerate()
    {
        record[i * 4..i * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    let mut h = Sha256::new();
    h.update(record);
    h.update(dk3);
    h.finalize().into()
}

pub(crate) fn cbc_decrypt(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), Error> {
    cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
        .expect("AES key/IV length")
        .decrypt_padded::<NoPadding>(data)
        .map_err(|_| Error::Malformed("unaligned CBC storage"))?;
    Ok(())
}

pub(crate) fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub(crate) fn derived_key(content_id: &[u8; 36], passcode: &[u8; 32], index: u32) -> [u8; 32] {
    let mut padded_id = [0; 48];
    padded_id[..36].copy_from_slice(content_id);
    let mut hash = Sha256::new();
    hash.update(Sha256::digest(index.to_be_bytes()));
    hash.update(Sha256::digest(padded_id));
    hash.update(passcode);
    hash.finalize().into()
}

pub(crate) fn pfs_material(key: &[u8; 32], seed: &[u8], index: u32) -> [u8; 32] {
    let mut input = [0; 20];
    input[..4].copy_from_slice(&index.to_le_bytes());
    input[4..].copy_from_slice(seed);
    hmac(key, &input)
}

pub(crate) fn xts(material: &[u8; 32]) -> Xts128<Aes128> {
    Xts128::new(
        Aes128::new_from_slice(&material[16..]).unwrap(),
        Aes128::new_from_slice(&material[..16]).unwrap(),
    )
}

#[cfg(test)]
mod known_answers {
    use super::*;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
    }

    #[test]
    fn rfc4231_case_1_hmac_sha256() {
        assert_eq!(
            hmac(&[0x0b; 20], b"Hi There"),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn nist_sp800_38a_f2_2_cbc_aes128() {
        let key = hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex::<16>("000102030405060708090a0b0c0d0e0f");
        let mut ciphertext = hex::<64>(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        );
        cbc_decrypt(&mut ciphertext, &key, &iv).unwrap();
        assert_eq!(
            ciphertext,
            hex(
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
            )
        );
    }

    #[test]
    fn independent_pfs_derivation_and_xts_sector() {
        // Original public synthetic inputs; Python hashlib/hmac + OpenSSL-backed
        // cryptography oracle, reproduced by tests/reference/check-outer-image.py.
        let key = std::array::from_fn(|i| i as u8);
        let seed: [u8; 16] = std::array::from_fn(|i| i as u8);
        let material = pfs_material(&key, &seed, 1);
        assert_eq!(
            material,
            hex("76be34e86d4a3793c4f2af46f63879f41b876753b3609b58c497052fc4f416b6")
        );
        assert_eq!(
            pfs_material(&key, &seed, 2),
            hex("e9d9d5c076c2b31e0a95557f14f36f20b99cfcc788f7c09e640ada5f49eeb7bd")
        );
        let mut sector: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        xts(&material).encrypt_area(&mut sector, 4096, 16, xts_mode::get_tweak_default);
        assert_eq!(
            &sector[..32],
            &hex::<32>("ceed998c169a81d5e1ea5c383d78f1eb6999d121bddec95ecb297ec0865a6d70")
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&sector)),
            hex("af5cd198566f2d9370dfaf633d7c52c32e84f9390fadc8f16e0947d55a63b092")
        );
    }

    #[test]
    fn independent_legacy_passcode_zero_and_nonzero_seed_vectors() {
        // Cross-checked with pinned L/F algorithms and independent Python/OpenSSL;
        // recipe/origins: docs/crypto-unblocking-findings.md, public synthetic data.
        let id = b"ZZ0000-CUSA00000_00-SYNTHETIC0000000";
        let passcode = std::array::from_fn(|i| 0x21 + i as u8);
        let keys: Vec<u8> = (0..7).flat_map(|i| derived_key(id, &passcode, i)).collect();
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(keys)),
            hex("5d9db1f987ef961cb0f904b8a7637a4be7e1bd3836f002dcb475eb0d2fce8473")
        );
        let image = crate::outer_image::legacy_image_key(
            std::str::from_utf8(id).unwrap(),
            std::str::from_utf8(&passcode).unwrap(),
        )
        .unwrap();
        assert_eq!(image, derived_key(id, &passcode, 1));
        for (seed, expected_material, expected_cipher, expected_hmac) in [
            (
                [0; 16],
                "b02114543bfb205623678c02f21df7e9619816e0d22bdb6da979a20d68a38914",
                "828b51da8f9f02e413b94ae8040419b20f15de95229ca73d77a949b217f4e2c5",
                "188040fd26cada2fb26e36e22fcbfc8ee657f7e7ceb0da9b04263b51d417aae5",
            ),
            (
                std::array::from_fn(|i| i as u8),
                "53c45751d99c9076986bf98b72e9e094cbac6e97faeee65bfc5ca85961ed97e1",
                "9cd2b41a557c5c3e1d50cb27453f8cb99ba7b083c0f8bb499608f41e7d56330a",
                "92b7aceb3bbfdc8f96852005816c4bbf6532fa042dc803d445342869dde6b78f",
            ),
        ] {
            let enc = pfs_material(&image, &seed, 1);
            let signing = pfs_material(&image, &seed, 2);
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest([enc, signing].concat())),
                hex(expected_material)
            );
            let mut sector: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
            let mut padded = sector.clone();
            padded.resize(65536, 0);
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest(hmac(&signing, &padded))),
                hex(expected_hmac)
            );
            xts(&enc).encrypt_area(&mut sector, 4096, 19, xts_mode::get_tweak_default);
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest(sector)),
                hex(expected_cipher)
            );
        }
        for (id, passcode) in [
            ("invalid", "short"),
            (
                std::str::from_utf8(id).unwrap(),
                "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
            ),
        ] {
            assert!(crate::outer_image::legacy_image_key(id, passcode).is_err());
        }
    }
}
