extern crate crypto;

use std::fs;

use cyptopals::aes_cbc_decrypt;

/// Decrypt AES CBC
fn main() {
    let line = fs::read_to_string("./files/aes_cbc.txt").unwrap();
    let cipher = base64::decode(&line.replace("\n", "")).unwrap();

    let plain = aes_cbc_decrypt(
        &cipher.clone(),
        b"YELLOW SUBMARINE".to_vec().as_ref(),
        &b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());

    println!("{}", String::from_utf8(plain).unwrap())
}
