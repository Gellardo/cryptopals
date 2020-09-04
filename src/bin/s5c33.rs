//! # Implement DH
//! ```
//! given p (prime), g (generator)
//! A = g**a % p with random a % p
//! B = g**b % p with random b % p
//! s = B**a % p = A**b % p
//! ```
//! Use the parameters from the challenge for p and g (NIST recommendation).

use cyptopals::dh::begin_dh_nist;

fn main() {
    let alice = begin_dh_nist();
    let bob = begin_dh_nist();
    let a_pub = alice.gen_pub();
    let b_pub = bob.gen_pub();
    assert_eq!(alice.gen_shared(&b_pub), bob.gen_shared(&a_pub))
}
