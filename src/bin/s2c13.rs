extern crate rand;

use cyptopals::{aes_ecb_decrypt, aes_ecb_encrypt, pad_pkcs7, random_128_bit, unpad_pkcs7};

/// Encrypt a profile, but don't allow the email to contain '&' or '='
fn encrypt(email: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut plain = b"email=".to_vec();
    assert!(!email.contains(&('&' as u8)) && !email.contains(&('=' as u8)));
    plain.extend(email);
    plain.extend(b"&uid=10&role=user".to_vec());
    aes_ecb_encrypt(&pad_pkcs7(plain, 16), &key)
}

fn decrypt(cipher: Vec<u8>, key: &Vec<u8>) -> String {
    String::from_utf8(unpad_pkcs7(aes_ecb_decrypt(&cipher, key)).unwrap()).unwrap()
}

/// Cut&paste with ECB
fn main() {
    let blocksize = 16;
    let key = random_128_bit();

    let cipher = encrypt(b"foo@bar".to_vec(), &key);
    let plain = decrypt(cipher, &key);
    println!("profile: {}", plain);

    let prefix_len = plain.find("foo@bar").unwrap();
    let middle_len = plain.find("user").unwrap() - "foo@bar".len() - prefix_len;
    println!("check lengths: {} {} {} {}",
             plain.get(0..prefix_len).unwrap(),
             plain.get(prefix_len..(prefix_len + "foo@bar".len())).unwrap(),
             plain.get((prefix_len + "foo@bar".len())..(prefix_len + "foo@bar".len() + middle_len)).unwrap(),
             plain.get((prefix_len + middle_len + "foo@bar".len())..).unwrap());

    // get copyable block
    let mut malicious_email = vec![0x41u8; blocksize - prefix_len];
    malicious_email.extend(pad_pkcs7(b"admin".to_vec(), blocksize as u8));
    let malicious_block_2 = encrypt(malicious_email, &key).get(16..32).unwrap().to_owned();
    debug_assert_eq!(aes_ecb_decrypt(&malicious_block_2.to_vec(), &key), pad_pkcs7(b"admin".to_vec(), blocksize as u8));

    // Since we have a valid block with proper padding from the previous encryption,
    // we can replace the last block with our prepared block.
    // Only works because role is the last field.
    // Otherwise it would be crucial that the malicious text fits into exactly block or we are able to include '=' or '&'
    let genuine_profile = encrypt(vec![0x41u8; blocksize - (prefix_len + middle_len) % blocksize], &key);
    let mut evil_profile = genuine_profile.get(0..genuine_profile.len() - 16).unwrap().to_vec();
    evil_profile.extend(malicious_block_2);
    let decrypted_evil_profile = decrypt(evil_profile, &key);
    println!("'{}'", decrypted_evil_profile);
    assert!(decrypted_evil_profile.ends_with("role=admin"), "the profile says admin now");
}
