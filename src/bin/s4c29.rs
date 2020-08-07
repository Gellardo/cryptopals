//! # SHA1 length extension
//! The SHA1 hash represents the internal state after having finished digesting.
//! If the end of the data is controlled by the attacker (not a secret), we can extend the data.
//! To do so, the padding has to be appended to the data and then the internal state should be the same as at the end of the MAC.
//! Now we can start up our own SHA1-MAC implementation, insert the value into the internal state.
//! The MAC produced after adding arbitrary data will be valid.

use cyptopals::random_128_bit;
use cyptopals::sha1::MySha1;

fn main() {
    let key = random_128_bit();
    let data = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    let orig_mac = MySha1::keyed_mac(&key, &data);
    println!("Original Mac: {:?} / {:02x?}", orig_mac, orig_mac);
    println!();

    // Assume I just know the key length
    // (otherwise just iterate over the different sizes and if it works, you found the right length)
    let (malicous_data, mac2) = sha_extension_attack(key.len(), data, orig_mac);

    println!("malicious data: {}", base64::encode(&malicous_data));
    println!("malicious data: {}", hex::encode(&malicous_data));

    println!("expect: {:02x?}\ngot   : {:02x?}", MySha1::keyed_mac(&key, &malicous_data), mac2);
    assert!(MySha1::validate_mac(&key, &malicous_data, &mac2));
}

fn sha_extension_attack(keylen: usize, data: Vec<u8>, orig_mac: [u32; 5]) -> (Vec<u8>, [u32; 5]) {
    let glue_padding = MySha1::padding(keylen + data.len());
    let malicious_suffix = b";admin=true".to_vec();
    let mut malicous_data = data.clone();
    malicous_data.append(&mut glue_padding.clone());
    malicous_data.append(&mut malicious_suffix.clone());

    // let state_from_mac : [u32; 5] = [1628389687, 1753611746, 3467952640, 466656266, 3558945814];
    // add dummy data to increment internal "data length" counter and a fixed len buffer
    let suffix_len = malicious_suffix.len();
    // the size in the final padding has to fit the whole message.
    let padded_input = MySha1::pad_fake_size(malicious_suffix, keylen + data.len() + glue_padding.len() + suffix_len);
    let mac2 = MySha1::hash_with_initial_state(orig_mac, padded_input);
    (malicous_data, mac2)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn works(){
        let key = b"1234".to_vec();//random_128_bit();
        let data = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
        let orig_mac = MySha1::keyed_mac(&key, &data);
        // Assume I just know the key length (otherwise just iterate sizes until it works)
        let (malicous_data, mac2) = sha_extension_attack(key.len(), data, orig_mac);
        assert_eq!(mac2, MySha1::keyed_mac(&key, &malicous_data));
    }
}
