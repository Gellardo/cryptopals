extern crate base64;
extern crate hex;

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

// DECRYPT
/// decrypt single byte xor and return the best 3 results
pub fn decrypt_xor_single_byte(cipher: Vec<u8>) -> Vec<(Score, u8, Vec<u8>)> {
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

/// Detect keylength and then decrypt a cipher text using repeating key xor
pub fn decrypt_xor_repeating_key(cipher: Vec<u8>) -> Vec<(Score, Vec<u8>, Vec<u8>)> {
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
        possible_decryptions.extend(decrypt_xor_repeating_key_size(&cipher, *keysize));
    }
    possible_decryptions.sort_by_key(|t| -t.0);
    possible_decryptions
}

/// decrypt repeating key xor with a known keysize and return the best result
pub fn decrypt_xor_repeating_key_size(cipher: &Vec<u8>, keysize: usize) -> Vec<(Score, Vec<u8>, Vec<u8>)> {
    let mut best_key = Vec::new();
    for i in 0..keysize {
        let mut ciphertext_i = Vec::new();
        for j in 0..cipher.len() {
            if j % keysize == i {
                ciphertext_i.push(cipher[j]);
            }
        }
        let options = decrypt_xor_single_byte(ciphertext_i);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance() {
        assert_eq!(hamming_distance(b"this is a test".to_vec(), b"wokka wokka!!!".to_vec()), 37);
    }
}
