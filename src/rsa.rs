use num_bigint::{BigInt, BigUint};
use num_integer::Integer;

use crate::primes::genprime;

pub struct PrivateKey {
    n: BigUint,
    d: BigUint,
}

pub struct PublicKey {
    n: BigUint,
    e: BigUint,
}

fn v2u(inp: &Vec<u8>) -> BigUint {
    BigUint::from_bytes_be(inp)
}

fn u2v(inp: &BigUint) -> Vec<u8> {
    inp.to_bytes_be()
}

/// compute x so that a * x == 1 mod m
/// Fails if gcd(a,m) != 1
fn invmod(a0: &BigUint, m0: &BigUint) -> BigUint {
    let one = BigInt::from(1u8);
    let (a0, m0) = (BigInt::from(a0.clone()), BigInt::from(m0.clone()));
    if m0 == one {
        return BigUint::from(1u8);
    }
    let (mut a, mut m, mut x0, mut inv) =
        (a0.clone(), m0.clone(), BigInt::from(0u8), BigInt::from(1u8));

    while a > one {
        inv = inv - (&a / &m) * &x0;
        a = a % &m;
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x0, &mut inv);
    }

    if inv < BigInt::from(0) {
        inv = inv + m0;
    }
    BigUint::from_bytes_be(inv.to_bytes_be().1.as_slice())
}

pub fn generate_key(size: u64) -> Option<(PrivateKey, PublicKey)> {
    let e = BigUint::from(3u8);
    // let (p, q) = (BigUint::from(3u8), BigUint::from(5u8));
    for _ in 0..20 {
        let (p, q) = (genprime(size / 2), genprime(size / 2));
        let n = &p * &q;
        let et = (&p - 1u8) * (&q - 1u8);
        //println!("n={}, e={}, et={}, ext_gcd={:?}", n, e, et, et.gcd(&e),);
        if e.gcd(&et) == BigUint::from(1u8) {
            // only possible if gcd (e, et) == 1
            // could use egcd to avoid failing invmod and and it produces the invmod result too
            let d = invmod(&e, &et);
            //println!("n={}, e={}, d={}", n.bits(), e, d);
            return Some((PrivateKey { n: n.clone(), d }, PublicKey { n, e }));
        }
    }
    None
}

impl PublicKey {
    pub fn encrypt(self, inp: &Vec<u8>) -> Vec<u8> {
        let exp = v2u(inp);
        assert!(exp < self.n, "input has to be smaller than modulus");
        let cipher = exp.modpow(&self.e, &self.n);
        u2v(&cipher)
    }
}

impl PrivateKey {
    pub fn decrypt(self, inp: &Vec<u8>) -> Vec<u8> {
        let exp = v2u(inp);
        assert!(exp < self.n, "input has to be smaller than modulus");
        let plain = exp.modpow(&self.d, &self.n);
        u2v(&plain)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn invmod_working() {
        // invmod(17, 3120) is 2753
        assert_eq!(
            invmod(&BigUint::from(17u8), &BigUint::from(3120u16)),
            BigUint::from(2753u16)
        )
    }

    #[test]
    fn encrypt_decrypt_short_text() {
        let (private, public) = generate_key(30).expect("did not find a key");
        let original_text = vec![5];
        let roundtrip = private.decrypt(&public.encrypt(&original_text));
        assert_eq!(roundtrip, original_text)
    }

    #[test]
    #[ignore] // not implemented yet
    fn encrypt_decrypt_long_text() {
        let (private, public) = generate_key(30).expect("did not find a key");
        let original_text = vec!['a' as u8; 512];
        let roundtrip = private.decrypt(&public.encrypt(&original_text));
        assert_eq!(roundtrip, original_text)
    }
}
