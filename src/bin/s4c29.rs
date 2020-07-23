//! # SHA1 length extension
//! The SHA1 hash represents the internal state after having finished digesting.
//! If the end of the data is controlled by the attacker (not a secret), we can extend the data.
//! To do so, the padding has to be appended to the data and then the internal state should be the same as at the end of the MAC.
//! Now we can start up our own SHA1-MAC implementation, insert the value into the internal state.
//! The MAC produced after adding arbitrary data will be valid.

use cyptopals::random_128_bit;
use cyptopals::sha1::{Sha1, padding};
use crypto::digest::Digest;
use std::iter::FromIterator;

fn main() {
    let key = b"1234".to_vec();//random_128_bit();
    // let data = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    let data = b"comment1=cooking".to_vec();
    let mac = Sha1::keyed_mac(&key, &data);
    println!("Original Mac: {:?} / {:02x?}", mac, mac);
    println!();

    // Assume I just know the key length
    // (otherwise just iterate over the different sizes and if it works, you found the right length)
    let mut glue_padding = padding(key.len() + data.len());
    let mut malicious_suffix = b";admin=true";
    let mut malicous_data = data.clone();
    malicous_data.append(&mut glue_padding);
    malicous_data.append(&mut malicious_suffix.to_vec());
    // TODO manual from print in keyed mac
    let state_from_mac : [u32; 5] = [1628389687, 1753611746, 3467952640, 466656266, 3558945814];
    let mut sha1 = Sha1::new();
    // add dummy data to increment internal "data length" counter and a fixed len buffer
    sha1.input(&vec![0u8;key.len()]);
    sha1.input(&data);
    sha1.input(&glue_padding);
    sha1.set_state(state_from_mac);
    println!("new state: {:?}, {:x?}", sha1.get_state(), sha1.get_state());
    sha1.input(malicious_suffix);
    let mac2 = sha1.result_vec();

    println!("malicious data: {}", base64::encode(&malicous_data));
    println!("malicious data: {}", hex::encode(&malicous_data));
    // TODO the final hash is wrong, so probably `set_state` does not work correctly? (no longer the default though)
    println!("expect: {:02x?}\ngot   : {:02x?}", Sha1::keyed_mac(&key, &malicous_data), mac2);
    // assert!(Sha1::validate_mac(&key, &malicous_data, &mac2));
}
