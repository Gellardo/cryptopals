/// # CBC bitflipping: Generate arbitrary text in decrypted CBC ciphertext
///
/// Requires:
/// - knowledge of the encrypted plain text of at least one block (since we need change less than 16 bytes)
/// - the garbled plaintext block to not break the processing in the `is_admin` function
///
/// CBC means that a bitflip in `cipher_block_i`:
/// - garbles `plain_block_i`
/// - produces (`plain_block_i+1` ^ `bitflips`)
///
/// If we know the plaintext of `plain_block_i+1`, we can use these targeted bitflips to make arbitrary changes to the original plain text.
/// We can introduce a `bitflips` vector, so that `intended_plain = plain_block_i+1 ^ bitflips` to the previous block.
/// Also, the prefix is luckily static and exactly 2 blocks long.
/// Most time was spent converting `Vec<u8>` into a `String` because of the decryption errors.
///
///
/// ## Being less detectable with more capabilities
/// I thought about being able to manipulate the ciphertext to produce non-garbled text.
/// I don't think it is possible in the current setup of not knowing the decrypted plain_text.
/// One could propagate errors backwards until we reach the iv, also requiring that we can freely manipulate that.
///
/// Assuming `iv||c_0||c_1||c_2` from `p_0||p_1||p_2` wbere `p_2` is the user input and `m_2` the intended ciphertext.
/// For this excercise, I already implemented it so that a bitflip `b_1` results in:
/// ```
/// decrypt(iv||c_0||c_1^b_1||c_2) = p_0||p'_1||m_2
/// ```
/// Now we can repeat the process, *if* we get to know garbled output (e.g. from error messages :) `p'_1`:
/// ```
/// b_0 = p'_1 ^ p_1
/// decrypt(iv||c_0^b_0||c_1^b_1||c_2) = p'_0||(p'_1^b_0)||m_2 = p'_0||(p'_1^p'_1^p_1)||m_2 = p'_0||p_1||m_2
/// ```
/// And a last step, which produces the an appropriate iv:
/// ```
/// b_iv = p'_0 ^ p_0
/// decrypt(iv^b_iv||c_0^b_0||c_1^b_1||c_2) = p'_0^b_iv||p_1||m_2 = p_0||p_1||m_2
/// ```
/// So if we give the `is_admin` logic the malicious `iv' = iv ^ b_iv`, the resulting plaintext looks like the original except that `p_2` has been replaced by `m_2`.
/// This could probably also be extended for changing multiple blocks
extern crate rand;

use std::iter::FromIterator;

use cyptopals::{aes_cbc_decrypt, aes_cbc_encrypt, pad_pkcs7, random_128_bit, unpad_pkcs7, xor};

/// Encrypt a profile, but don't allow the email to contain '&' or '='
fn encrypt(mut userdata: Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let mut plain = b"comment1=cooking%20MCs;userdata=".to_vec();
    println!("prefix lenght: {}", plain.len());
    userdata = userdata.iter().filter(|e| **e != ';' as u8 && **e != '=' as u8).map(|e| *e).collect();
    plain.extend(userdata);
    println!("prefix+user lenght: {}", plain.len());
    plain.extend(b";comment2=%20like%20a%20pound%20of%20bacon".to_vec());
    println!("prefix+user+suffix lenght: {}", plain.len());
    aes_cbc_encrypt(pad_pkcs7(plain, 16), &key, &iv.to_owned())
}

fn is_admin(cipher: Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> bool {
    let decrypted = unpad_pkcs7(aes_cbc_decrypt(cipher, key, iv)).unwrap();
    let ascii = String::from_iter(decrypted.iter().map(|b| *b as char));
    println!("decrypted: {:?}", ascii);
    ascii.contains(";admin=true;")
}

fn main() {
    let blocksize = 16;
    let key = random_128_bit();
    let iv = random_128_bit();

    let user_plain = b"0123456789012345".to_vec();
    let intended_plain = b"AAAAA;admin=true".to_vec();
    let bitflips = xor(user_plain.clone(), &intended_plain);
    let mut cipher = encrypt(user_plain, &key, &iv);

    let range_previous_block = blocksize * 1..blocksize * 2;
    let previous_block = cipher.get(range_previous_block.clone()).unwrap().to_vec();
    let replacement = xor(previous_block, &bitflips);
    cipher.splice(range_previous_block, replacement);

    let admin = is_admin(cipher, &key, &iv);
    println!("we are admin: {}", admin);
}
