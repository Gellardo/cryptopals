extern crate crypto;

use std::fs;

use crypto::aessafe;
use crypto::aessafe::AesSafe128Decryptor;
use crypto::symmetriccipher::BlockDecryptor;

/// Decrypt AES ECB
///
/// Nice to know: `openssl enc -d -aes-128-ecb -K '59454c4c4f57205355424d4152494e45' -a -in files/aes_ecb.txt`
/// *Can't* use `YELLOW SUBMARINE` since 1) `-k` seems to hash it 2) `-K` expects hex, therefore `hexdump -C` FTW
fn main() {
    let line = fs::read_to_string("./files/aes_ecb.txt").unwrap();
    let cipher = base64::decode(&line.replace("\n", "")).unwrap();

    let aes_dec: AesSafe128Decryptor = aessafe::AesSafe128Decryptor::new(b"YELLOW SUBMARINE");

    let mut output = Vec::new();
    for i in (0..cipher.len()).step_by(16) {
        let mut out = [0; 16];
        aes_dec.decrypt_block(cipher[i..i + 16].as_ref(), &mut out);
        output.extend_from_slice(&out);
    }
    println!("{}", String::from_utf8(output.to_vec()).unwrap());
}
