//! # Bitflipping with CTR (like c16)
//! Of course bitflipping still works.
//! Works even better than cbc, since wie don't destroy the previous block with the bitflip.
//! Apart from that, the attack is the same, guess/know the offset of my plaintext, calculate the controlled bitflips and apply them.
//! Only had to change the encryption functions and the offset.
use std::fs;

use cyptopals::{aes_ctr, random_128_bit, xor};
use std::iter::FromIterator;

/// Encrypt a profile, but don't allow the email to contain '&' or '='
fn encrypt(mut userdata: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut plain = b"comment1=cooking%20MCs;userdata=".to_vec();
    println!("prefix lenght: {}", plain.len());
    userdata = userdata.iter().filter(|e| **e != ';' as u8 && **e != '=' as u8).map(|e| *e).collect();
    plain.extend(userdata);
    println!("prefix+user lenght: {}", plain.len());
    plain.extend(b";comment2=%20like%20a%20pound%20of%20bacon".to_vec());
    println!("prefix+user+suffix lenght: {}", plain.len());
    aes_ctr(&plain, &key, 0)
}

fn is_admin(cipher: Vec<u8>, key: &Vec<u8>) -> bool {
    let decrypted = aes_ctr(&cipher, &key, 0);
    let ascii = String::from_iter(decrypted.iter().map(|b| *b as char));
    println!("decrypted: {:?}", ascii);
    ascii.contains(";admin=true;")
}

fn main() {
    let key = random_128_bit();

    let user_plain = b"0123456789012345".to_vec();
    let intended_plain = b"AAAAA;admin=true".to_vec();
    let plain_len = user_plain.len();
    let magic_offset = 16*2;
    let bitflips = xor(user_plain.clone(), &intended_plain);
    let mut cipher = encrypt(user_plain, &key);

    let range_previous_block =  magic_offset..magic_offset + plain_len;
    let previous_block = cipher.get(range_previous_block.clone()).unwrap().to_vec();
    let replacement = xor(previous_block, &bitflips);
    cipher.splice(range_previous_block, replacement);

    let admin = is_admin(cipher, &key);
    println!("we are admin: {}", admin);
}
