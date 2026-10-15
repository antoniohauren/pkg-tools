use aes::{
    Aes128, Aes256,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use sha1::{Digest, Sha1};

pub(super) const fn hex<const N: usize>(s: &str) -> [u8; N] {
    let bytes = s.as_bytes();
    assert!(bytes.len() == N * 2);
    let mut out = [0; N];
    let mut i = 0;
    while i < N * 2 {
        let c = bytes[i];
        let n = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex constant"),
        };
        out[i / 2] = out[i / 2] * 16 + n;
        i += 1;
    }
    out
}

pub(super) const FREE: [u8; 16] = hex("72f990788f9cff745725f08e4c128387");
pub(super) const OMAC2: [u8; 16] = hex("6ba52976efda16ef3c339fb2971e256b");
pub(super) const OMAC3: [u8; 16] = hex("9b515feacf75064981aa604d91a54e97");
pub(super) const KLIC: [u8; 16] = hex("f2fbca7a75b04edc1390638ccdfdd1ee");

pub(super) fn xor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    std::array::from_fn(|i| a[i] ^ b[i])
}
pub(super) fn aes(key: &[u8; 16], data: [u8; 16], decrypt: bool) -> [u8; 16] {
    let c = Aes128::new(key.into());
    let mut b = data.into();
    if decrypt {
        c.decrypt_block(&mut b);
    } else {
        c.encrypt_block(&mut b);
    }
    b.into()
}
pub(super) fn cbc(key: &[u8], mut iv: [u8; 16], data: &mut [u8], decrypt: bool) {
    assert!(data.len().is_multiple_of(16));
    for part in data.as_chunks_mut::<16>().0 {
        let original = *part;
        let mut block = if decrypt { original } else { xor(original, iv) }.into();
        match key.len() {
            16 => {
                let c = Aes128::new_from_slice(key).unwrap();
                if decrypt {
                    c.decrypt_block(&mut block);
                } else {
                    c.encrypt_block(&mut block);
                }
            }
            32 => {
                let c = Aes256::new_from_slice(key).unwrap();
                if decrypt {
                    c.decrypt_block(&mut block);
                } else {
                    c.encrypt_block(&mut block);
                }
            }
            _ => unreachable!(),
        }
        let result: [u8; 16] = block.into();
        part.copy_from_slice(&if decrypt { xor(result, iv) } else { result });
        iv = if decrypt { original } else { result };
    }
}
pub(super) fn ctr(key: &[u8; 16], iv: [u8; 16], data: &mut [u8]) {
    let c = Aes128::new(key.into());
    let counter = u128::from_be_bytes(iv);
    for (i, chunk) in data.chunks_mut(16).enumerate() {
        let mut block = counter.wrapping_add(i as u128).to_be_bytes().into();
        c.encrypt_block(&mut block);
        for (b, k) in chunk.iter_mut().zip(block) {
            *b ^= k;
        }
    }
}
pub(super) fn cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    fn double(b: [u8; 16]) -> [u8; 16] {
        let n = u128::from_be_bytes(b);
        ((n << 1) ^ if n >> 127 != 0 { 0x87 } else { 0 }).to_be_bytes()
    }
    let k1 = double(aes(key, [0; 16], false));
    let blocks = data.len().div_ceil(16).max(1);
    let mut state = [0; 16];
    for i in 0..blocks {
        let part = &data[i * 16..data.len().min(i * 16 + 16)];
        let mut block = [0; 16];
        block[..part.len()].copy_from_slice(part);
        if i + 1 == blocks {
            block = if part.len() == 16 {
                xor(block, k1)
            } else {
                block[part.len()] = 0x80;
                xor(block, double(k1))
            };
        }
        state = aes(key, xor(state, block), false);
    }
    state
}
pub(super) fn hmac(key: &[u8], data: &[u8]) -> [u8; 20] {
    assert!(key.len() <= 64);
    let mut pad = [0x36; 64];
    for (p, k) in pad.iter_mut().zip(key) {
        *p ^= k;
    }
    let mut h = Sha1::new();
    h.update(pad);
    h.update(data);
    let inner = h.finalize();
    for p in &mut pad {
        *p ^= 0x36 ^ 0x5c;
    }
    let mut h = Sha1::new();
    h.update(pad);
    h.update(inner);
    h.finalize().into()
}
pub(super) fn rap_key(rap: [u8; 16]) -> [u8; 16] {
    let mut key = aes(&hex("869f7745c13fd890ccf29188e3cc3edf"), rap, true);
    let p = [12, 3, 6, 4, 1, 11, 15, 8, 2, 7, 0, 5, 10, 14, 13, 9];
    let e1: [u8; 16] = hex("a93e1fd67c55a329b75fdda62a95c7a5");
    let e2: [u8; 16] = hex("67d45da3296d006a4e7c537bf5538c74");
    for _ in 0..5 {
        for i in p {
            key[i] ^= e1[i];
        }
        for i in (1..16).rev() {
            key[p[i]] ^= key[p[i - 1]];
        }
        let mut borrow = 0;
        for i in p {
            let value = key[i].wrapping_sub(borrow);
            if borrow != 1 || value != 255 {
                borrow = u8::from(value < e2[i]);
            }
            key[i] = value.wrapping_sub(e2[i]);
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nist_cmac_and_cbc_vectors() {
        let k = hex("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(cmac(&k, b""), hex("bb1d6929e95937287fa37d129b756746"));
        let mut b = hex::<16>("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(cmac(&k, &b), hex("070a16b46b4d4144f79bdd9dd04a287c"));
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        cbc(&k, iv, &mut b, false);
        assert_eq!(b, hex("7649abac8119b246cee98e9b12e9197d"));
        cbc(&k, iv, &mut b, true);
        assert_eq!(b, hex("6bc1bee22e409f96e93d7e117393172a"));
    }
    #[test]
    fn rap_known_answers() {
        // Independently calculated with Python cryptography / RPCS3's RAP transform.
        assert_eq!(rap_key([0; 16]), hex("a0b21c84d2ef63699e75c34eed055380"));
        assert_eq!(
            rap_key(std::array::from_fn(|i| i as u8)),
            hex("56b28b74268d9326cf9b3a522e7215b4")
        );
        assert_eq!(rap_key([255; 16]), hex("680415c81c0459e2ee941857315550d7"));
    }
}
