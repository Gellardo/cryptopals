extern crate crypto;

use std::collections::HashSet;
use std::fs;

/// Find the aes ecb encrypted ciphertext
fn main() {
    let lines = fs::read_to_string("./files/find_the_ecb.txt").unwrap();

    let blocksize = 16;
    let mut scored_ciphers = Vec::new();
    for (i, line) in lines.split("\n").enumerate() {
        let cipher = base64::decode(&line).unwrap();
        let mut score = 0;
        let mut blocks = HashSet::new();
        for i in (0..cipher.len()).step_by(blocksize) {
            let block = cipher.get(i..i + blocksize);
            match block {
                Some(b) => {
                    score += if blocks.contains(&b) { 1 } else { 0 };
                    blocks.insert(b);
                }
                None => {}
            }
        }
        // could probably get 'better' threshold by estimation using the birthday paradox
        if score > 0 {
            scored_ciphers.push((score, i))
        }
    }

    println!("(score, line), where score > 0 indicates an ecb cipher, at least for these short ciphertexts");
    println!("{:?}", scored_ciphers)
}
