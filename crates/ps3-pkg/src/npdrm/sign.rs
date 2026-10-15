//! Loader curve 0x27 and the public 3.55 NPDRM signing key.
//! This signs a compatibility format, not a private application credential.
use num_bigint_dig::BigUint;
use sha1::{Digest, Sha1};

type Point = Option<(BigUint, BigUint)>;
fn number(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).unwrap()
}
fn p() -> BigUint {
    number("9be59bc21226f8a144313b235e89a9c89a69cabb")
}
fn n() -> BigUint {
    number("9be59bc21226f8a144304638d96be3234965be65")
}
fn generator() -> Point {
    Some((
        number("46853050e0342e747cda37bc437d53a90290a8ab"),
        number("3996e93f7a0ee6232f18eabf34cf5805d94fdb6c"),
    ))
}
fn add(left: &Point, right: &Point) -> Point {
    let (Some((x, y)), Some((u, v))) = (left, right) else {
        return left.clone().or_else(|| right.clone());
    };
    let p = p();
    let slope = if x == u {
        if (y + v) % &p == BigUint::from(0u8) {
            return None;
        }
        (BigUint::from(3u8) * x * x + &p - BigUint::from(3u8))
            * (BigUint::from(2u8) * y).modpow(&(&p - BigUint::from(2u8)), &p)
            % &p
    } else {
        (v + &p - y) * (u + &p - x).modpow(&(&p - BigUint::from(2u8)), &p) % &p
    };
    let xx = (&slope * &slope + &p + &p - x - u) % &p;
    let yy = (&slope * (x + &p - &xx) + &p - y) % &p;
    Some((xx, yy))
}
fn multiply(mut scalar: BigUint, mut point: Point) -> Point {
    let mut out = None;
    while scalar != BigUint::from(0u8) {
        if &scalar & BigUint::from(1u8) != BigUint::from(0u8) {
            out = add(&out, &point);
        }
        point = add(&point, &point);
        scalar >>= 1;
    }
    out
}
pub(super) fn sign(data: &[u8]) -> [u8; 48] {
    let hash = Sha1::digest(data);
    let d = number("9ac6b22a056ba9e0b6d1520f28a57a3135483f9f");
    let n = n();
    let z = BigUint::from_bytes_be(&hash);
    for attempt in 0u32.. {
        // Deterministic per-message nonce; this format's signing key is public.
        let mut h = Sha1::new();
        h.update(b"pkg-tools SELF signature");
        h.update(hash);
        h.update(attempt.to_be_bytes());
        let k =
            BigUint::from_bytes_be(&h.finalize()) % (&n - BigUint::from(1u8)) + BigUint::from(1u8);
        let r = multiply(k.clone(), generator()).unwrap().0 % &n;
        let s = k.modpow(&(&n - BigUint::from(2u8)), &n) * (&z + &r * &d) % &n;
        if r == BigUint::from(0u8) || s == BigUint::from(0u8) {
            continue;
        }
        let mut out = [0; 48];
        for (value, end) in [(r, 21), (s, 42)] {
            let b = value.to_bytes_be();
            out[end - b.len()..end].copy_from_slice(&b);
        }
        return out;
    }
    unreachable!()
}
#[cfg(test)]
mod tests {
    use super::super::crypto::hex;
    use super::*;
    #[test]
    fn public_key_and_signature_equation() {
        let d = number("9ac6b22a056ba9e0b6d1520f28a57a3135483f9f");
        let q = multiply(d, generator());
        let (x, y) = q.clone().unwrap();
        assert_eq!(
            x.to_bytes_be(),
            hex::<20>("3995c390c9f7fbbab124a1c14e70f9741a5e6bdf")
        );
        assert_eq!(
            y.to_bytes_be(),
            hex::<20>("17a605d88239652c8ea7d5fc9f24b30546c1e44b")
        );
        let sig = sign(b"SELF header");
        let n = n();
        let r = BigUint::from_bytes_be(&sig[..21]);
        let s = BigUint::from_bytes_be(&sig[21..42]);
        let w = s.modpow(&(&n - BigUint::from(2u8)), &n);
        let z = BigUint::from_bytes_be(&Sha1::digest(b"SELF header"));
        let check = add(
            &multiply(z * &w % &n, generator()),
            &multiply(&r * w % &n, q),
        )
        .unwrap();
        assert_eq!(check.0 % n, r);
    }
}
