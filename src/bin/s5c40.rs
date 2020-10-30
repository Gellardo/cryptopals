//! # Break RSA with e=3 with Broadcast Attack
//! Encrypt with RSA without Padding.
//! If that is done 3 times to the same plain text with different pubkeys, the plaintext can be obtained.
//!
//! Uses the Chinese Remainder Theorem.

use cyptopals::rsa;

fn main() {
    let plain = b"as".to_vec();
    let mut v = vec![];
    for _ in 0..3 {
        let (_, p) = rsa::generate_key(100).expect("need a key");
        v.push((p.encrypt(&plain), p))
    }
    assert_eq!(rsa::decrypt_e3_unpadded_broadcast(v), plain);
}

#[cfg(test)]
mod test {
    use super::main;

    #[test]
    fn it_works() {
        main()
    }
}
