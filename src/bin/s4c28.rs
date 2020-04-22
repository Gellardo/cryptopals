//! # Rust SHA1 implementation
use cyptopals::sha1::Sha1;
use crypto::digest::Digest;

fn main() {
    let mut sha1 = Sha1::new();
    sha1.input(&[44;5]);
    println!("Sha1 works: {}", sha1.result_str());
}
