//! # MD4 length extension
//! like c29, but with MD4

use cyptopals::md4::MyMd4;
use cyptopals::random_128_bit;

fn main() {
    let key = random_128_bit();
    let data =
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    let orig_mac = MyMd4::keyed_mac(&key, &data);
    println!("Original Mac: {:?} / {:02x?}", orig_mac, orig_mac);
    println!();

    // Assume I just know the key length
    // (otherwise just iterate over the different sizes and if it works, you found the right length)
    let (malicous_data, mac2) = md4_extension_attack(key.len(), data, orig_mac);

    println!("malicious data: {}", base64::encode(&malicous_data));
    println!("malicious data: {}", hex::encode(&malicous_data));

    println!(
        "expect: {:02x?}\ngot   : {:02x?}",
        MyMd4::keyed_mac(&key, &malicous_data),
        mac2
    );
    assert!(MyMd4::validate_mac(&key, &malicous_data, &mac2));
}

fn md4_extension_attack(keylen: usize, data: Vec<u8>, orig_mac: [u32; 4]) -> (Vec<u8>, [u32; 4]) {
    let glue_padding = MyMd4::padding(keylen + data.len());
    let malicious_suffix = b";admin=true".to_vec();
    let mut malicous_data = data.clone();
    malicous_data.append(&mut glue_padding.clone());
    malicous_data.append(&mut malicious_suffix.clone());

    // let state_from_mac : [u32; 5] = [1628389687, 1753611746, 3467952640, 466656266, 3558945814];
    // add dummy data to increment internal "data length" counter and a fixed len buffer
    let suffix_len = malicious_suffix.len();
    // the size in the final padding has to fit the whole message.
    let padded_input = MyMd4::pad_fake_size(
        malicious_suffix,
        keylen + data.len() + glue_padding.len() + suffix_len,
    );
    let mac2 = MyMd4::hash_with_initial_state(orig_mac, padded_input);
    (malicous_data, mac2)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn works() {
        let key = b"1234".to_vec(); //random_128_bit();
        let data = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
            .to_vec();
        let orig_mac = MyMd4::keyed_mac(&key, &data);
        // Assume I just know the key length (otherwise just iterate sizes until it works)
        let (malicous_data, mac2) = md4_extension_attack(key.len(), data, orig_mac);
        assert_eq!(mac2, MyMd4::keyed_mac(&key, &malicous_data));
    }
}
