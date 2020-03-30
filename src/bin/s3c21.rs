//! # Implement a Mersenne Twister RNG (MT19937)

use cyptopals::MT19937::MersenneTwister;

fn main() {
    println!("See c319, kthxbye");
    let mut rng = MersenneTwister::new();
    rng.seed(1);
    rng.extract_number();
}
