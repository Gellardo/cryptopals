//! # Clone a MT19937 PRNG
//! Untempering the values, we obtain the exact values of the internal state.
//! Assuming, we know how many values are produced, we can determine, when the next `twist` operation will happen.
//! After that, we collect 624 (= number of internal u32) and untemper them.
//! If we don't know, when the next `twist` will happen, we can record 2*264 values instead and just try all possible 624 subsequences of 624 values.
//!
//! Using a cryptographic hash instead of `temper` would make recovery of the untempered value harder but not impossible
//! The input space is relatively small with 2**32 possible inputs, e.g. SHA-1 hashing can do 3+MHashes/s, which is <2**10 seconds per u32.
//! Brute-force can therefore be used to obtain possible unhashed values, making cloning harder but not impossible.
//!
//! One way to harden this PRNG would be to use secret information during the tempering.
//! If the PRNG generates a random 'key', e.g. by hashing the seed, we can increase the searchspace and integrating that into the tempering, e.g. using an HMAC.
//! But this time, the seed is to small for this to matter, since 2**32 can't resist a brute-force for relatively quick operations.

use std::error::Error;

use rand::random;

use cyptopals::mt19937::{clone, MersenneTwister};

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = MersenneTwister::new();
    // simulate seeding at unixtime a random amount of seconds (<=400) ago, -1 to allow looping starting at 1
    rng.seed(random());
    let mut outputs: Vec<u32> = Vec::new();
    for _ in 0..624 {
        outputs.push(rng.extract_number()?)
    }
    assert_eq!(clone(outputs).extract_number(), rng.extract_number());
    Ok(())
}
