//! # Rust SHA1 implementation
use cyptopals::sha1::MySha1;
use cyptopals::u32_be_bytes;

fn main() {
    let sha1 = MySha1::hash(vec![44; 5]);
    println!("Sha1 works: {}", hex::encode(u32_be_bytes(&sha1)));
}
