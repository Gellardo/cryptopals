//! # Break random access r/w CTR
//! The attacker has the ability to write arbitrary plaintext at arbitrary offsets in the ciphertext.
//! Using that and examining the resulting ciphertext, he can decrypt the original plain text.
//!
//! Thinking about harddrive encryption, using ctr (or any stream cipher really) would be bad.
//! As soon as a certain position is written again, 1) the same (now reversible) xor is performed and
//! 2) only that one byte is changed.
//! A useful encryption would need another encryption primitive operating on plaintext(/-derivatives)
//! to include a non-trivially reversible component.
use std::fs;

use cyptopals::{aes_ctr, aes_ecb_decrypt, random_128_bit};

fn edit(cipher: &Vec<u8>, key: &Vec<u8>, offset: usize, new: &Vec<u8>) -> Vec<u8> {
    assert!(offset + new.len() <= cipher.len());
    let mut plain = aes_ctr(&cipher, &key, 0);
    &plain.splice(offset..offset + new.len(), new.iter().cloned());
    // we can hardcode the nonce to 0, since it is valid for the whole ciphertext
    // and the text says nothing about rotating (which implies reencrypting everything)
    aes_ctr(&plain, &key, 0)
}

/// Slow and steady: decrypt one byte at a time
///
/// The ctr mode has to generate the same keystream byte for a certain position everytime.
/// So if we know the new ciphertext byte for that position, we can obtain the keystream byte using xor.
/// Rinse and repeat until every byte is known.
/// Could be sped up if we use larger sections of known plaintext to obtain larger keystream sections.
fn break_random_rw_ctr(mut cipher: Vec<u8>, apicall: &mut dyn Fn(&Vec<u8>, usize, &Vec<u8>) -> Vec<u8>) -> Vec<u8> {
    println!("{:?}", cipher.get(0..10));
    let len = cipher.len();
    let mut plain = Vec::new();
    let replacement = ['a' as u8];
    for i in 0..len {
        print!(".");
        if i % 100 == 99 {
            println!();
        }
        let original = cipher[i];
        cipher = apicall(&cipher, i, &replacement.to_vec());

        // ctr generates the same keystream, so o ^ c' = p ^ k ^ 'a' ^ k = p ^ 'a'
        plain.push(original ^ cipher[i] ^ replacement[0]);
        cipher = apicall(&cipher, i, &vec![*plain.get(i).unwrap()]); // revert change
    }
    plain
}

fn main() {
    let line = fs::read_to_string("./files/aes_ecb.txt").unwrap();
    let cipher = base64::decode(&line.replace("\n", "")).unwrap();

    let plain = aes_ecb_decrypt(&cipher, b"YELLOW SUBMARINE".to_vec().as_ref());
    let key = random_128_bit();
    let cipher = aes_ctr(&plain, &key, 0);
    let mut api = |cipher: &Vec<u8>, offset: usize, new: &Vec<u8>| { edit(cipher, &key, offset, new) };
    assert_eq!(break_random_rw_ctr(cipher, &mut api), plain);
}
