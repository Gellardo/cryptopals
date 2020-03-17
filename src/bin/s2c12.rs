extern crate rand;

use cyptopals::{aes_ecb_encrypt, compare, detect_blocksize, detect_ecb, pad_pkcs7, random_128_bit};

/// Extract an appended secret from the encryption blackbox
///
/// Requires the blackbox to have the following properties:
///   - blackbox(text) = enc(text||secret)
///   - blackbox(text) stays the same for consecutive calls
///   - blackbox uses pkcs7 padding for the plaintext (for the stopping condition)
fn decrypt_fixed_suffix(blackbox: &mut dyn Fn(Vec<u8>) -> Vec<u8>, blocksize: usize) -> Vec<u8> {
    let secret_len = blackbox(vec![]).len();
    let mut found = Vec::new();
    for i in 0..secret_len {
        let mut prefix = vec![31; blocksize - 1 - (i % blocksize)];
        let to_match = blackbox(prefix.clone());
        prefix.extend(&found);
        let found_len = found.len();
        let found_blocks = found.len() / blocksize;
        for c in 0..255u8 {
            prefix.push(c);
            // compare only useful block = the one containing the border between prefix and secret
            // previous blocks are equal due to construction, blocks after contain an additional copy of secret
            let working_block = (found_blocks * 16)..((found_blocks + 1) * 16);
            if blackbox(prefix.clone()).get(working_block.clone()).unwrap() == to_match.get(working_block).unwrap() {
                println!("@{} found: {}", i, c);
                found.push(c);
                break;
            }
            prefix.pop();
        }
        // if we have some chars left, but could not find a match, it is probably because we are trying to decode padding
        // the padding changes though: Let's assume the padding is '\x02\x02'
        // we first try to find the first char, with a prefix so that it is the last char before a new block.
        // Therefore the padding changes to '\x01' which we find.
        // This leaves us with '\x01\x??' whose ciphertext can never match a plaintext ending in '\x02\x02'.
        if found.len() == found_len {
            assert_eq!(found.pop().unwrap(), 1u8, "If this is pkcs7 padding, we expect a 1");
            println!("break");
            break;
        }
    }
    found
}

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

    let decrypted_secret = decrypt_fixed_suffix(&mut encrypt_blackbox, blocksize);
    println!("decrypted secret matches: {} (len: {}, {})", decrypted_secret == secret_data, decrypted_secret.len(), secret_data.len());
    assert!(compare(&decrypted_secret, &secret_data));
}
