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
    let dk3 = unwrap(&keys[256 + 3 * 256..256 + 4 * 256], false)?;
    check_digest(&dk3, &keys[32 + 3 * 32..32 + 4 * 32])?;
    let material = entry_material(entry, &dk3);
    cbc_decrypt(image, &material[16..], &material[..16])?;
    let ekpfs = unwrap(image, true)?;
    // The wrapped image key may already include the new-crypt seed transform;
    // entry-key digest 1 describes the passcode-derived key, not this image key.
    Ok((dk3, ekpfs))
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
