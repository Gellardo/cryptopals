/// # CBC Padding Oracle
///
/// Requires:
/// - ciphertext + iv from cbc encryption
/// - oracle that returns true if decrypting a ciphertext has a valid padding and can be queried repeatedly
///
/// Idea: Go backwards through the ciphertext, guessing one byte at a time
/// - by bitflipping the previous block, we can change the value of the last byte.
/// - try out all bitflips until the oracle answers with true with bitflip `b`
/// - we now know the last byte: `0x01 ^ b`
/// - for the next byte, choose a bitflip that changes the last byte to `0x02`
/// - repeat the previous process until the oracle returns a true, then the second to last byte is `0x02 ^ b'`
/// - repeat until every byte is known, discarding blocks from matching once all bytes have been found
///
/// Possible edgecase and improvements (from research):
/// - the block already has valid padding (ends on `02 02`) we have 2 possible valid found bytes: `02` and `01`.
///   can be caught by checking if block by its own already returns a valid padding
/// - we only need to take 2 consecutive blocks to decrypt the second one. This should make the decryption operations faster
extern crate rand;

use cyptopals::{aes_cbc_decrypt, aes_cbc_encrypt, pad_pkcs7, random_128_bit, unpad_pkcs7, xor};

fn get_oracle() -> (Vec<u8>, Vec<u8>, Box<dyn Fn(&Vec<u8>, &Vec<u8>) -> bool>) {
    let options = vec![
        base64::decode("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
        base64::decode("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
        base64::decode("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
        base64::decode("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
        base64::decode("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
        base64::decode("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
        base64::decode("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
        base64::decode("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
        base64::decode("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
        base64::decode("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
    ];
    let plain = options.get(rand::random::<usize>() % options.len()).unwrap().to_owned().unwrap();
    println!("plain: {:?}", String::from_utf8(plain.clone()));
    let key = random_128_bit();
    let iv = random_128_bit();
    let cipher = aes_cbc_encrypt(&pad_pkcs7(plain, 16), &key, &iv);
    (cipher, iv, Box::new(move |cipher, iv| unpad_pkcs7(aes_cbc_decrypt(&cipher, &key, iv)).is_ok()))
}

fn cbc_padding_oracle(blackbox: &mut dyn Fn(&Vec<u8>, &Vec<u8>) -> bool, previous_block: &Vec<u8>, to_decrypt: &Vec<u8>) -> Vec<u8> {

    to_decrypt.clone()
}

fn main() {
    let (cipher, iv, mut oracle) = get_oracle();
    println!("oracle works: {}", oracle(&cipher, &iv));

    cbc_padding_oracle( &mut oracle, &iv, &cipher[0..16].to_vec());
}
