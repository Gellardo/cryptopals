//! # Implement a Mersenne Twister RNG (MT19937)
use std::num::Wrapping;

const N: usize = 624;
const M: usize = 397;

const F: Wrapping<u32> = Wrapping(1812433253);

pub struct MersenneTwister { state: [Wrapping<u32>; N], index: usize }

impl MersenneTwister {
    pub fn new() -> Self {
        //Pseudo code from wikipedia
        // Create a length N array to store the state of the generator
        MersenneTwister {
            state: [Wrapping(0); N],
            index: N + 1,
        }
    }

    pub fn seed(&mut self, seed: u32) {
        self.index = N;
        self.state[0] = Wrapping(seed);
        for i in 1..N { // loop over each element
            // lowest W bits of function
            self.state[i] = F * (self.state[i - 1] ^ (self.state[i - 1] >> 30)) + Wrapping(i as u32);
        }
    }

    pub fn extract_number(&mut self) -> Result<u32, String> {
        if self.index >= N {
            if self.index > N {
                return Err("Generator was never seeded".to_string());
            }
            self.twist()
        }

        let Wrapping(mut y) = self.state[self.index];
        y ^= y >> 11;
        y ^= (y << 7) & 0x9D2C5680;
        y ^= (y << 15) & 0xEFC60000;
        y ^= y >> 18;

        self.index += 1;
        Ok(y)
    }

    fn twist(&mut self) {
        let a = Wrapping(0x9908B0DF);
        let lower_mask = Wrapping((1 << 31) - 1);// That is, the binary number of r 1's
        let upper_mask = !lower_mask;
        for i in 0..N {
            let x: Wrapping<u32> = (self.state[i] & upper_mask) + (self.state[(i + 1) % N] & lower_mask);
            let mut x_a = x >> 1;
            if (x.0 % 2) != 0 { // lowest bit of x is 1
                x_a = x_a ^ a
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a
        }
        self.index = 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn rng_working_correctly() {
        let mut rng = MersenneTwister::new();
        rng.seed(1);
        debug_assert_eq!(rng.extract_number().unwrap(), 1791095845);
        debug_assert_eq!(rng.extract_number().unwrap(), 4282876139);
        debug_assert_eq!(rng.extract_number().unwrap(), 3093770124);
    }

    #[test]
    #[ignore]
    fn bench_with_same_struct() {
        let start = SystemTime::now();
        let mut rng = MersenneTwister::new();
        for i in 1..10_000 {
            rng.seed(i);
            rng.extract_number();
        }
        println!("Took {:?} seconds", start.elapsed().unwrap())
    }

    #[test]
    #[ignore]
    fn bench_with_new_struct() {
        let start = SystemTime::now();
        for i in 1..10_000 {
            let mut rng = MersenneTwister::new();
            rng.seed(0);
            rng.extract_number();
        }
        println!("Took {:?} seconds", start.elapsed().unwrap())
    }

    #[test]
    #[ignore]
    fn bench_with_single_seed() {
        let start = SystemTime::now();
        let mut rng = MersenneTwister::new();
        rng.seed(0);
        for i in 1..10_000 {
            rng.extract_number();
        }
        println!("Took {:?} seconds", start.elapsed().unwrap())
    }
}
