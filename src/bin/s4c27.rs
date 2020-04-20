//! # CBC key recovery if iv=key
//! Attack requires >= 3 encrypted blocks and access to the decrypted result.
//! More specifically, 1 actually encrypted first block and the ability to decrypt >=3.
//!
//! Process given by the challenge, with some notes here why it works:
//! 1. IV = KEY and Enc(P1,P2,P3) = C1, C2, C3
//!   - C1 = Enc(P1 ^ KEY), C2 = Enc(P2 ^ C1), C3 = Enc(P3 ^ C2)
//! 2. Replace the first 3 blocks with C1,0,C1
//! 3. Decrypt and obtain plain text P1', P2', P3'
//!   - P1' = Dec(C1) ^ KEY = Dec(Enc(P1 ^ KEY)) ^ KEY = P1
//!   - P2' is irrelevant, C2'=0 is necessary as the 'IV' for P3'
//!   - P3' = Dec(C3') ^ C2' = Dec(C1) ^ 0 = Dec(Enc(P1 ^ KEY)) ^ 0 = P1 ^ KEY
//!   - P1' ^ P3' = P1 ^ KEY ^ P1 = KEY
//!
//! We basically construct 2 decryptions, one with an unknown IV (= KEY) and one with a known one (= 0).
//! Since xoring by 0 leaves the CBC masking from the encryption intact, xoring it with the original plaintext yields the IV.
//! The IV = KEY, so we are done.
extern crate rand;

use std::iter::FromIterator;

use cyptopals::{aes_cbc_decrypt, aes_cbc_encrypt, pad_pkcs7, random_128_bit, unpad_pkcs7, xor};

/// Encrypt a profile, but don't allow the email to contain '&' or '='
fn encrypt(mut userdata: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut plain = b"comment1=cooking%20MCs;userdata=".to_vec();
    println!("prefix lenght: {}", plain.len());
    userdata = userdata.iter().filter(|e| **e != ';' as u8 && **e != '=' as u8).map(|e| *e).collect();
    plain.extend(userdata);
    println!("prefix+user lenght: {}", plain.len());
    plain.extend(b";comment2=%20like%20a%20pound%20of%20bacon".to_vec());
    println!("prefix+user+suffix lenght: {}", plain.len());
    aes_cbc_encrypt(&pad_pkcs7(plain, 16), &key, &key)
}

/// Return decrypted string if there are illegal characters, simulating logging the decrypted plaintext somewhere and then parsing that log message.
/// Not really part of the exercise to parse Vec<u8> from a String.
fn is_admin(cipher: Vec<u8>, key: &Vec<u8>) -> Result<bool, Vec<u8>> {
    let decrypted = unpad_pkcs7(aes_cbc_decrypt(&cipher, key, key)).unwrap();
    let ascii = String::from_iter(decrypted.iter().map(|b| *b as char));
    println!("decrypted: {:?}", ascii);
    if !ascii.chars().all(|b| b.is_ascii_alphanumeric() || b.is_ascii_graphic()) {
        return Err(decrypted);
    }
    Ok(ascii.contains(";admin=true;"))
}

fn main() {
    let blocksize = 16;
    let key = random_128_bit();

    let user_plain = b"AAAAAAAAAAAAAAAA".to_vec();
    let mut cipher = encrypt(user_plain, &key);
    is_admin(cipher.clone(), &key).expect("should still work");

    cipher.splice(blocksize * 1..blocksize * 2, vec![0; blocksize]);
    cipher.splice(blocksize * 2..blocksize * 3, cipher.get(0..blocksize).unwrap().to_vec());

    let decrypted = is_admin(cipher, &key).expect_err("unlucky, try again");
    let recovered_key = xor(decrypted.get(0..blocksize).unwrap().to_vec(),
                            &decrypted.get(blocksize * 2..blocksize * 3).unwrap().to_vec());
    assert_eq!(recovered_key, key);
}
