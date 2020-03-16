extern crate base64;
extern crate hex;

use std::collections::HashSet;

use crypto::aessafe;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};

pub fn xor(s1: Vec<u8>, s2: Vec<u8>) -> Vec<u8> {
    assert_eq!(s1.len(), s2.len(), "parameters must be the same length");
    s1.iter().zip(s2).map(|(u1, u2)| { u1 ^ u2 }).collect()
}

pub fn xor_single_byte(plain: Vec<u8>, key: u8) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(plain.len());
    for _ in 0..plain.len() {
        keystream.push(key);
    }
    xor(plain, keystream)
}

pub fn xor_repeating_key(plain: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(plain.len());
    for i in 0..plain.len() {
        keystream.push(key[i % key.len()]);
    }
    xor(plain, keystream)
}

pub fn aes_ecb_encrypt(plain: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    assert!(plain.len() % 16 == 0 && key.len() == 16);
    let aes_enc = aessafe::AesSafe128Encryptor::new(key);
    let mut cipher = Vec::new();
    for i in (0..plain.len()).step_by(16) {
        let mut out = [0; 16];
        aes_enc.encrypt_block(&plain[i..i + 16], &mut out);
        cipher.extend_from_slice(out.as_ref());
    }
    cipher
}

pub fn aes_ecb_decrypt(cipher: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    assert!(cipher.len() % 16 == 0 && key.len() == 16);
    let aes_dec = aessafe::AesSafe128Decryptor::new(key);
    let mut plain = Vec::new();
    for i in (0..cipher.len()).step_by(16) {
        let mut out = [0; 16];
        aes_dec.decrypt_block(&cipher[i..i + 16], &mut out);
        plain.extend_from_slice(out.as_ref());
    }
    plain
}

pub fn aes_cbc_encrypt(plain: Vec<u8>, key: &Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    assert!(plain.len() % 16 == 0 && key.len() == 16 && iv.len() == 16);
    let aes_enc = aessafe::AesSafe128Encryptor::new(key);
    let mut cipher = Vec::new();
    let mut prev_cipher_block = iv;
    for i in (0..plain.len()).step_by(16) {
        let current_block = xor(plain[i..i + 16].to_vec(), prev_cipher_block);
        let mut out = [0; 16];
        aes_enc.encrypt_block(current_block.as_ref(), &mut out);
        cipher.extend_from_slice(out.as_ref());
        prev_cipher_block = out.to_vec();
    }
    cipher
}

pub fn aes_cbc_decrypt(cipher: Vec<u8>, key: &Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    assert!(cipher.len() % 16 == 0 && key.len() == 16 && iv.len() == 16);
    let aes_dec = aessafe::AesSafe128Decryptor::new(key);
    let mut plain = Vec::new();
    let mut prev_cipher_block = iv;
    for i in (0..cipher.len()).step_by(16) {
        let mut out = [0; 16];
        aes_dec.decrypt_block(&cipher[i..i + 16], &mut out);
        plain.extend(xor(out.to_vec(), prev_cipher_block));
        prev_cipher_block = cipher[i..i + 16].to_vec();
    }
    plain
}

// DECRYPT
/// Break single byte xor and return the best 3 results
pub fn break_xor_single_byte(cipher: Vec<u8>) -> Vec<(Score, u8, Vec<u8>)> {
    let mut possible_best: Vec<(Score, u8, Vec<u8>)> = Vec::new();
    for key in 0..=255u8 {
        let guess = xor_single_byte(cipher.clone(), key);
        let rating = rate_plain(&guess);
        possible_best.push((rating, key, guess));
    }
    // reverse sorting
    possible_best.sort_by_key(|t| { -t.0 });
    possible_best.get(..3).unwrap().to_vec()
}

/// Detect keylength and then break a cipher text using repeating key xor
pub fn break_xor_repeating_key(cipher: Vec<u8>) -> Vec<(Score, Vec<u8>, Vec<u8>)> {
    // 1. guess the keysize
    // if we have the right keysize, each compared byte pair hd(c1,c2) = hd(p1^k^p2^k) = hd(p1^p2)
    // This code therefore assumes that the difference between plaintext bytes is smaller than all other combinations.
    // we have to use multiple blocks to ensure statistics work in our favor though
    let mut normalized = Vec::new();
    for keysize in 1..40 {
        let mut sum = 0;
        for i in 0..10 {
            sum += hamming_distance(cipher[i * keysize..(i + 1) * keysize].to_vec(), cipher[(i + 1) * keysize..(i + 2) * keysize].to_vec());
        }
        normalized.push((sum as f32 / 10f32 / keysize as f32, keysize));
    }
    normalized.sort_by(|t1, t2| t1.0.partial_cmp(&t2.0).unwrap());
    println!("{:?}", normalized);

    // 2. decrypt with the best X keylengths
    let mut possible_decryptions = Vec::new();
    for (_, keysize) in normalized.get(0..3).unwrap() {
        possible_decryptions.extend(break_xor_repeating_key_size(&cipher, *keysize));
    }
    possible_decryptions.sort_by_key(|t| -t.0);
    possible_decryptions
}

/// Break repeating key xor with a known keysize and return the best result
pub fn break_xor_repeating_key_size(cipher: &Vec<u8>, keysize: usize) -> Vec<(Score, Vec<u8>, Vec<u8>)> {
    let mut best_key = Vec::new();
    for i in 0..keysize {
        let mut ciphertext_i = Vec::new();
        for j in (i..cipher.len()).step_by(keysize) {
            ciphertext_i.push(cipher[j])
        }
        let options = break_xor_single_byte(ciphertext_i);
        best_key.push(options[0].clone());
    }
    let key: Vec<u8> = best_key.iter().map(|t| t.1).collect();
    let plain = xor_repeating_key(cipher.clone(), key.clone());
    vec![(rate_plain(&plain), key, plain)]
}

// UTIL
pub type Score = i32;

/// Rate a clear text for how good it fits an english text
///
/// any chars, spaces and punctuation indicates at least the plaintext resembles something readable
/// punish unrecognized characters
pub fn rate_plain(s: &Vec<u8>) -> Score {
    let mut res: Score = 0;
    for c in s {
        if *c >= 'a' as u8 && *c <= 'z' as u8 { // most text is lowercase
            res += 7;
        } else if *c == ' ' as u8 || *c >= 'A' as u8 && *c <= 'Z' as u8 { // a lot of spaces and uppercase
            res += 5;
        } else if *c == '\'' as u8 || *c == '\n' as u8 || *c == '.' as u8 { // few special chars
            res += 2;
        } else if (*c as char).is_whitespace() {
            res += 1;
        } else {
            res -= 10;
        }
    }
    res
}

/// Pad block using the pkcs#7 padding
/// ```
/// use cyptopals::pad_pkcs7;
/// assert_eq!(pad_pkcs7(b"YELLOW SUBMARINE".to_vec(), 20), b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec());
/// ```
pub fn pad_pkcs7(mut block: Vec<u8>, blocksize: u8) -> Vec<u8> {
    let missing_bytes = blocksize - (block.len() % blocksize as usize) as u8;
    if missing_bytes != 0 {
        for _ in 0..missing_bytes {
            block.push(missing_bytes)
        }
    }
    block
}

/// perhaps i am going to use it some time in the future
fn _compare_letter_frequency() {
    let _letter_frequency = vec![
        // from wikipedia
        ('e', 12.702),
        ('t', 9.356),
        ('a', 8.167),
        ('o', 7.507),
        ('i', 6.966),
        ('n', 6.749),
        ('s', 6.327),
        ('h', 6.094),
        ('r', 5.987),
        ('d', 4.253),
        ('l', 4.025),
        ('u', 2.758),
        ('w', 2.560),
        ('m', 2.406),
        ('c', 2.202),
        ('f', 2.228),
        ('g', 2.015),
        ('y', 1.994),
        ('p', 1.929),
        ('b', 1.492),
        ('k', 1.292),
        ('v', 0.978),
        ('j', 0.153),
        ('x', 0.150),
        ('q', 0.095),
        ('z', 0.077),
    ];
}

fn hamming_distance(s1: Vec<u8>, s2: Vec<u8>) -> u32 {
    assert_eq!(s1.len(), s2.len());
    s1.iter().zip(s2).map(|(c1, c2)| (c1 ^ c2).count_ones()).sum()
}

pub fn random_128_bit() -> Vec<u8> {
    let mut vec = Vec::new();
    for _ in 0..16 {
        vec.push(rand::random());
    }
    vec
}

/// Tries progressively longer plain texts, until there is a new block added.
/// The difference between the previous and the new length is the blocksize.
/// Maximum blocksize detected is 64 bytes.
pub fn detect_blocksize(blackbox: &mut dyn Fn(Vec<u8>) -> Vec<u8>) -> Option<usize> {
    let l0 = blackbox(vec![0]).len();
    for i in 0..64 {
        let vec1 = vec![0; i + 1];
        let l1 = blackbox(vec1).len();
        if l1 > l0 {
            return Some(l1 - l0);
        }
    }
    None
}

pub fn detect_ecb(blackbox: &mut dyn Fn(Vec<u8>) -> Vec<u8>, blocksize: usize) -> bool {
    let cipher = blackbox(vec![0; 3 * blocksize]);
    let mut blocks = HashSet::new();
    for i in (0..cipher.len()).step_by(16) {
        let block = cipher.get(i..i + 16);
        match block {
            Some(b) => {
                if blocks.contains(&b) { return true; };
                blocks.insert(b);
            }
            None => {}
        }
    }
    false
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_dist() {
        assert_eq!(hamming_distance(b"this is a test".to_vec(), b"wokka wokka!!!".to_vec()), 37);
    }

    #[test]
    fn aes_ecb() {
        let plain = b"YELLOW SUBMARINEYELLOW SUBMARINE".to_vec();
        let key = b"YELLOW SUBMARINE".to_vec();
        let cipher = aes_ecb_encrypt(plain.clone(), key.clone());
        assert_eq!(
            cipher,
            hex::decode("d1aa4f6578926542fbb6dd876cd20508d1aa4f6578926542fbb6dd876cd20508").unwrap(),
            "cipher"
        );
        assert_eq!(aes_ecb_decrypt(cipher, key), plain, "plain");
    }

    #[test]
    fn aes_cbc() {
        let plain = b"YELLOW SUBMARINEYELLOW SUBMARINE".to_vec();
        let key = b"YELLOW SUBMARINE".to_vec();
        let iv = hex::decode("00000000000000000000000000000000").unwrap();
        let cipher = aes_cbc_encrypt(plain.clone(), key.clone(), iv.clone());
        assert_eq!(
            cipher,
            hex::decode("d1aa4f6578926542fbb6dd876cd20508eaed974f65b7a3a9240d36daef1a31ea").unwrap(),
            "cipher"
        );
        assert_eq!(
            aes_cbc_decrypt(cipher, key.clone(), iv),
            plain,
            "plain"
        );
    }
}
