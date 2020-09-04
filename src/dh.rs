use std::ops::Rem;

use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

pub struct DhSession {
    p: BigUint,
    g: BigUint,
    a: BigUint,
}

pub fn p_nist() -> BigUint {
    BigUint::parse_bytes(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514\
            a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e\
            9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a16\
            3bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966\
            d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
            .as_bytes(),
        16,
    )
    .expect("is valid hex")
}

pub fn g_nist() -> BigUint {
    BigUint::from(2u8)
}

pub fn begin_dh_nist() -> DhSession {
    begin_dh(p_nist(), g_nist())
}

pub fn begin_dh(p: BigUint, g: BigUint) -> DhSession {
    let mut rng = thread_rng();
    let a: BigUint = rng.gen_biguint(p.bits()).rem(&p);
    DhSession { p, g, a }
}

trait PowMod {
    fn pow_mod(self, a: Self, p: Self) -> Self;
}

impl PowMod for u32 {
    fn pow_mod(self, a: u32, p: u32) -> u32 {
        let mut res = 1;
        for _ in 0..a {
            res = res * self % p;
        }
        res
    }
}

impl DhSession {
    pub fn gen_pub(&self) -> BigUint {
        self.g.modpow(&self.a, &self.p)
    }
    pub fn gen_shared(&self, a_pub: &BigUint) -> BigUint {
        a_pub.modpow(&self.a, &self.p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_powmod() {
        assert_eq!(2u32.pow(16) % 5, 2u32.pow_mod(16, 5));
        assert_eq!(
            ((2u32.pow(16) % 5) * (2u32.pow(16) % 5)) % 5,
            2u32.pow_mod(16, 5)
        )
    }

    #[test]
    fn test_dh_example() {
        let p = BigUint::from(37u32);
        let g = BigUint::from(5u32);
        let alice = DhSession {
            p: p.clone(),
            g: g.clone(),
            a: BigUint::from(2u32),
        };
        let bob = DhSession {
            p,
            g,
            a: BigUint::from(3u32),
        };
        let a_pub = alice.gen_pub();
        assert_eq!(a_pub, BigUint::from(25u32));
        let b_pub = bob.gen_pub();
        assert_eq!(b_pub, BigUint::from(125u32 % 37));
        assert_eq!(alice.gen_shared(&b_pub), bob.gen_shared(&a_pub))
    }

    #[test]
    fn test_nist_params() {
        let alice = begin_dh_nist();
        let bob = begin_dh_nist();
        assert_eq!(
            alice.gen_shared(&bob.gen_pub()),
            bob.gen_shared(&alice.gen_pub())
        )
    }
}
