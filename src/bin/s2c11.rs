extern crate rand;

use rand::{Rng, thread_rng};
use rand::distributions::Standard;

use cyptopals::{aes_cbc_encrypt, aes_ecb_encrypt, detect_ecb, pad_pkcs7, random_128_bit};

use crate::Encryption::{CBC, ECB};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum Encryption {
    ECB,
    CBC,
}

fn encryption_oracle(plain: Vec<u8>, enc: Encryption) -> Vec<u8> {
    let mut rng = thread_rng();
    let key = random_128_bit();
    let iv = random_128_bit();
    let mut plain_ext = Vec::new();
    plain_ext.extend(rng.sample_iter(Standard).take(rng.gen_range(5, 10)).collect::<Vec<u8>>());
    plain_ext.extend(plain);
    plain_ext.extend(rng.sample_iter(Standard).take(rng.gen_range(5, 10)).collect::<Vec<u8>>());

    if enc == CBC {
        aes_cbc_encrypt(&pad_pkcs7(plain_ext, 16), &key, &iv)
    } else {
        aes_ecb_encrypt(&pad_pkcs7(plain_ext, 16), &key)
    }
}

/// ECB/CBC encryption oracle
///
/// relatively simple, we only need to input a long string (>=3*blocksize) of the same bytes.
/// ECB will then produce the same block twice, no matter what the prepended/appended bytes are.
/// 3 * blocksize = worstcase if 1 byte in first block is unknown, we loose 15 bytes to that and need another 32 to have 2 known blocks.
/// This ignores, that the pre/postfix has 5-10 bytes, which makes the required size even smaller.
fn main() {
    let iterations = 10000;
    let mut correct = 0;
    for _ in 0..iterations {
        let enc = if rand::random() { ECB } else { CBC };
        let mut blackbox = |plain| { encryption_oracle(plain, enc) };
        let is_ecb = detect_ecb(&mut blackbox, 16);
        if enc == ECB && is_ecb || enc == CBC && !is_ecb {
            correct += 1;
        }
    }

    println!("Correctly detected {} out of {}", correct, iterations)
}
