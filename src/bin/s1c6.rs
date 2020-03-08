use std::fs;

use cyptopals::decrypt_xor_repeating_key;

/// Find the ciphertext that is probably encrypted with single byte xor
fn main() {
    let line = fs::read_to_string("./files/break_repeating_key_xor.txt").unwrap();
    let cipher = base64::decode(&line.replace("\n", "")).unwrap();

    let plain = decrypt_xor_repeating_key(cipher);

    println!("{:?}", plain);
}
