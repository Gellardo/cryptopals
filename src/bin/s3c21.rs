//! # Implement a Mersenne Twister RNG (MT19937)

use cyptopals::mt19937::MersenneTwister;

fn main() {
    let mut rng = MersenneTwister::new();
    rng.seed(1);
    rng.extract_number().expect("a number");
}
