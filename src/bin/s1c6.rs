use std::fs;

use cyptopals::break_xor_repeating_key;

/// Find the ciphertext that is probably encrypted with single byte xor
fn main() {
    let line = fs::read_to_string("./files/break_repeating_key_xor.txt").unwrap();
    let cipher = base64::decode(&line.replace("\n", "")).unwrap();

    let options = break_xor_repeating_key(cipher);

    for (score, key, plain) in options {
        println!("{}:{}, {:?}: {:?}", score, key.len(), String::from_utf8(key), String::from_utf8(plain))
    }
}
