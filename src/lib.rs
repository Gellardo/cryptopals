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


// SCORING
pub type Score = i32;

/// Rate a clear text for how good it fits an english text
pub fn rate_plain(s: &Vec<u8>) -> Score {
    let mut res = 0;
    for c in s {
        if *c >= 'a' as u8 && *c <= 'z' as u8 {
            res += 5;
        } else if *c >= 'A' as u8 && *c <= 'Z' as u8 {
            res += 5;
        } else if (*c as char).is_whitespace() {
            res += 1;
        }
    }
    res
}
