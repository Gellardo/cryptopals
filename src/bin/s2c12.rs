extern crate rand;

use cyptopals::{aes_ecb_encrypt, pad_pkcs7, random_128_bit, detect_blocksize, detect_ecb};


/// Byte at a time ecb decryption (simple)
fn main() {
    let secret_data = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
    let key = random_128_bit();
    let mut encrypt_blackbox = |mut plain: Vec<u8>| {
        plain.extend_from_slice(secret_data.as_slice());
        aes_ecb_encrypt(pad_pkcs7(plain, 16), &key)
    };

    let blocksize = detect_blocksize(&mut encrypt_blackbox).unwrap();
    println!("Cipher has blocksize {} bytes", blocksize);
    println!("Cipher is using ecb: {}", detect_ecb(&mut encrypt_blackbox, blocksize));
}
