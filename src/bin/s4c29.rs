//! # Rust SHA1 implementation
//! Implemented by monkey-patching the rust std-implementation of Sha1, only having to expose the state.
//!
//! Keyed Mac does not allow blindly tamering with the data, since any trivial change to data or key changes the hash of the concatenated string.
//! As long as we have no clue about the key, we can't reproduce the hash.

use cyptopals::random_128_bit;
use cyptopals::sha1::Sha1;

fn main() {
    let key = random_128_bit();
    let data = random_128_bit();
    assert_eq!(Sha1::keyed_mac(key.clone(), data.clone()),
               Sha1::keyed_mac(key.clone(), data.clone()));
    let mut tampered_key = key.clone();
    tampered_key.push(12);
    let mut tampered_data = data.clone();
    tampered_key.push(13);
    assert_ne!(Sha1::keyed_mac(key.clone(), data.clone()),
               Sha1::keyed_mac(tampered_key.clone(), data.clone()));
    assert_ne!(Sha1::keyed_mac(key.clone(), data.clone()),
               Sha1::keyed_mac(key.clone(), tampered_data.clone()));
    assert_ne!(Sha1::keyed_mac(key.clone(), data.clone()),
               Sha1::keyed_mac(tampered_key.clone(), tampered_data.clone()));
}
