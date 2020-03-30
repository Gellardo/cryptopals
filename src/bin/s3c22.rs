//! # Break predictably seeded Mersenne Twister RNG
//! The RNG is seeded with the unix timestamp (milliseconds since 1970) and then 'waits' a random amount of seconds.
//! There are not that many possibilities, so we will just try all possible seeds from the last hour.
//!
//! This is still surprisingly slow. I wonder if it is my implementation or just the pure amount of computation.

use std::error::Error;
use std::time::SystemTime;

use rand::random;

use cyptopals::mt19937::MersenneTwister;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = MersenneTwister::new();
    // simulate seeding at unixtime a random amount of seconds (<=400) ago, -1 to allow looping starting at 1
    let seed: u128 = dbg!(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis() - (random::<u128>() % 400_000)) - 1;
    rng.seed(seed as u32);
    let first_out = rng.extract_number()?;

    // find the seed within the last hour
    let current = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis();
    let mut rng = MersenneTwister::new();
    for i in 1..(60 * 60 * 1000) {
        if i % 1000 == 0 { print!("."); }
        if i % 60000 == 0 { println!(); }
        let seed: u128 = current - i;
        rng.seed(seed as u32);
        if rng.extract_number()? == first_out {
            println!("!");
            println!("Found the seed: {}", seed);
            break;
        }
    }
    Ok(())
}
