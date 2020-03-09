use std::fs;

use cyptopals::break_xor_single_byte;

/// Find the ciphertext that is probably encrypted with single byte xor
fn main() {
    let line = fs::read_to_string("./files/find_single_byte_xor.txt").unwrap();
    let lines: Vec<Vec<u8>> = line.split("\n")
        .filter(|x| x.len() > 2)
        .map(|x| x.trim())
        .map(|x| hex::decode(x).unwrap())
        .collect();
    let mut best_decryptions = Vec::new();
    for cipher in lines {
        let possible_best = break_xor_single_byte(cipher);
        best_decryptions.push(possible_best.first().unwrap().clone());
    }
    best_decryptions.sort_by_key(|t| -t.0);
    for i in 0..5 {
        let (score, key, text) = best_decryptions[i].clone();
        println!("{}, {}: {:?}", score, key, String::from_utf8(text));
    }
}
