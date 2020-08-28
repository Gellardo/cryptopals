//! # MT19937 as a stream cipher
//! By using a known plaintext, we can recover the keystream.
//! As demonstrated in c23, the sequence of PRNG outputs can then be used to reconstruct the internal state.
//! But since the challenge wants to use a 16 bit key, it is probably easier to use the recovered keystream to bruteforce those 16 bit.

use std::error::Error;

use rand::random;

use cyptopals::mt19937::stream_cipher;
use cyptopals::prepend_random_prefix;

/// Find the seed by brute forcing the encryption key, which is only a 16 bit key
fn recover_key() {
    let seed = random();
    let f = |plain: Vec<u8>| stream_cipher(&prepend_random_prefix(plain), seed);
    let cipher = f(vec![0u8; 10]);
    // offset of the known plaintext
    let offset = cipher.len() - 10;

    let plain = vec![0u8; cipher.len()];
    let mut recovered_seed = None;
    for s in 0..=65535u16 {
        if s % 1024 == 1023 {
            print!(".");
        }
        if s % 8192 == 8191 {
            println!();
        }
        if stream_cipher(&plain, s).get(offset..cipher.len()) == cipher.get(offset..cipher.len()) {
            println!("{}", s);
            recovered_seed = Some(s);
            break;
        }
    }

    assert_eq!(seed, recovered_seed.expect("no seed found"));
}

/// The way i read it, this would be another brute force attack. Which is boring.
///
/// Password = seed rng with now(), throw a few (hundred) bytes away, take 2-4 outputs as random password.
/// Reversing would only be a combination of the timebased brute force of previous exercises with matching a certain output pattern.
/// Skip.
fn password_reset_token() {
    // let current = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis() as u32;
}

fn main() -> Result<(), Box<dyn Error>> {
    password_reset_token();
    recover_key();
    Ok(())
}
