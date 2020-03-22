extern crate crypto;

use std::fs;

use cyptopals::aes_ecb_decrypt;

/// Decrypt AES ECB
///
/// Nice to know: `openssl enc -d -aes-128-ecb -K '59454c4c4f57205355424d4152494e45' -a -in files/aes_ecb.txt`
/// *Can't* use `YELLOW SUBMARINE` since 1) `-k` seems to hash it 2) `-K` expects hex, therefore `hexdump -C` FTW
fn main() {
    let line = fs::read_to_string("./files/aes_ecb.txt").unwrap();
    let cipher = base64::decode(&line.replace("\n", "")).unwrap();

    let output = aes_ecb_decrypt(&cipher, b"YELLOW SUBMARINE".to_vec().as_ref());
    println!("{}", String::from_utf8(output.to_vec()).unwrap());
}
