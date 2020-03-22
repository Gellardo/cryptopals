extern crate rand;
extern crate log;
extern crate env_logger;

use std::collections::HashSet;

use cyptopals::{aes_ecb_encrypt, compare, detect_blocksize, detect_ecb, pad_pkcs7, random_128_bit, extract_fixed_suffix};

/// Find a block in a ciphertext and return the starting offset
fn find_block(cipher: &Vec<u8>, block: &Vec<u8>) -> Option<usize> {
    let blocksize = block.len();
    'blocks: for i in 0..(cipher.len() / blocksize) {
        for j in 0..blocksize {
            if cipher[i * blocksize + j] != block[j] {
                continue 'blocks;
            }
        }
        return Some(i * blocksize);
    }
    None
}

#[test]
fn test_find_block() {
    assert_eq!(find_block(&vec![1, 2, 3, 4], &vec![2, 3]), None);
    assert_eq!(find_block(&vec![1, 2, 3, 4], &vec![3, 4]), Some(2usize));
}

fn find_first_duplicate_block(cipher: &Vec<u8>) -> Option<Vec<u8>> {
    let mut blocks = HashSet::new();
    for i in (0..cipher.len()).step_by(16) {
        let block = cipher.get(i..i + 16);
        match block {
            Some(b) => {
                if blocks.contains(&b) { return Some(b.to_vec()); };
                blocks.insert(b);
            }
            None => {}
        }
    }
    None
}


/// Byte at a time ecb decryption with a random (length and content) prefix
fn main() {
    env_logger::init();

    let secret_data = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
    let key = random_128_bit();
    let mut encrypt_blackbox = |plain: Vec<u8>| {
        // random length random prefix
        let mut plain_mod = random_128_bit();
        plain_mod.extend(random_128_bit());
        let to_drop: u8 = rand::random();
        for _ in 0..(to_drop % 31) {
            plain_mod.pop();
        }
        plain_mod.extend(plain);
        plain_mod.extend_from_slice(secret_data.as_slice());
        aes_ecb_encrypt(&pad_pkcs7(plain_mod, 16), &key)
    };

    let blocksize = detect_blocksize(&mut encrypt_blackbox).unwrap();
    println!("Cipher has blocksize {} bytes", blocksize);
    println!("Cipher is using ecb: {}", detect_ecb(&mut encrypt_blackbox, blocksize));

    // Use longer pattern to reduce probability of accidental matches in wrapped_blackbox
    // if we use AAAA, any random A at the end of the prefix might trick our detection later
    let plain_known = vec![0x41,0x42,0x43,0x44].repeat(4);
    let mut known_block = find_first_duplicate_block(&encrypt_blackbox(plain_known.repeat(2)));
    while known_block.is_none() {
        known_block = find_first_duplicate_block(&encrypt_blackbox(plain_known.repeat(2)));
    }
    let known_block = known_block.unwrap();
    println!("found marker block");


    // retry encryption (1/16 chance the random prefix fits) until we find the `known_block`.
    // We remove everything up to and including that block.
    // This way, the problem is reduced to the easy case, no unknown prefix left.
    let mut wrapped_blackbox = |plain: Vec<u8>| {
        loop {
            let mut plain_mut = plain_known.clone();
            plain_mut.extend(&plain);
            let mut potential_cipher = encrypt_blackbox(plain_mut);
            let position = find_block(&potential_cipher, &known_block);
            if position.is_some() {
                let cipher = potential_cipher.split_off(position.unwrap() + blocksize);
                // checking that removal works correctly
//                println!("removed {:?}", potential_cipher);
//                println!("known   {:?}", known_block);
//                println!("ret {:?}", cipher);
                return cipher;
            }
        }
    };

    let decrypted_secret = extract_fixed_suffix(&mut wrapped_blackbox, blocksize);
    println!("decrypted secret matches: {} (len: {}, {})", decrypted_secret == secret_data, decrypted_secret.len(), secret_data.len());
    assert!(compare(&decrypted_secret, &secret_data));
}
