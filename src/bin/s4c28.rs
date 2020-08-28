//! # Rust SHA1 implementation
use cyptopals::sha1::MySha1;
use crypto::digest::Digest;
use cyptopals::u32_be_bytes;

fn main() {
    let mut sha1 = MySha1::hash(vec![44;5]);
    println!("Sha1 works: {}", hex::encode(u32_be_bytes(&sha1)));
}
