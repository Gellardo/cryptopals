//! # Implement a Mersenne Twister RNG (MT19937)
use std::num::Wrapping;

const N: usize = 624;
const M: usize = 397;

const F: Wrapping<u32> = Wrapping(1812433253);

pub struct MersenneTwister {
    state: [Wrapping<u32>; N],
    index: usize,
}

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
        for i in 1..N {
            // loop over each element
            // lowest W bits of function
            self.state[i] =
                F * (self.state[i - 1] ^ (self.state[i - 1] >> 30)) + Wrapping(i as u32);
        }
    }

    pub fn extract_number(&mut self) -> Result<u32, String> {
        if self.index >= N {
            if self.index > N {
                return Err("Generator was never seeded".to_string());
            }
            self.twist()
        }

        let Wrapping(y) = self.state[self.index];
        self.index += 1;
        Ok(temper(y))
    }

    fn twist(&mut self) {
        let a = Wrapping(0x9908B0DF);
        let lower_mask = Wrapping((1 << 31) - 1); // That is, the binary number of r 1's
        let upper_mask = !lower_mask;
        for i in 0..N {
            let x: Wrapping<u32> =
                (self.state[i] & upper_mask) + (self.state[(i + 1) % N] & lower_mask);
            let mut x_a = x >> 1;
            if (x.0 % 2) != 0 {
                // lowest bit of x is 1
                x_a = x_a ^ a
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a
        }
        self.index = 0
    }
}

fn temper(mut x: u32) -> u32 {
    // println!("step 0: {}", x);
    x ^= x >> 11;
    // println!("step  1: {}", x);
    // println!("x'  : {:32b}", x);
    // println!("temp: {:32b}", (x<<7) & 0x9D2C5680);
    x ^= (x << 7) & 0x9D2C5680;
    // println!("step  2: {}", x);
    x ^= (x << 15) & 0xEFC60000;
    // println!("step 3: {}", x);
    x ^= x >> 18;
    // println!("step 4: {}", x);
    x
}

fn untemper(mut x: u32) -> u32 {
    // To untemper, we need to reverse every tempering operation in the reverse order.
    // To do so, we need to use the unchanged bits to undo the xor operation, since x^y^y = x.
    // This can require multiple operations to progressively obtain the necessary original bits to undo the xor.

    // reverse x ^= x >> 18;
    // x    : 0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m o p q r s t u v w
    // x>>18:                                     0 1 2 3 4 5 6 7 8 9 a b c d
    // x^x> : 0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m o p q r s t u v w
    // no changes in the relevent part for the xor, can be repeated to undo
    x ^= x >> 18;

    // reverse x ^= (x << 15) & 0xEFC60000;
    // x    : 0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m o p q r s t u v w
    // x<<15: f g h i j k l m o p q r s t u v w
    // &    : 1 1 1 0 1 1 1 1 1 1 0 0 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    // x^x< : 0'1'2'3 4'5'6'7'8'9'a b c d'e'f g h i j k l m o p q r s t u v w
    // f-w is unchanged in the result, so again, can be repeated to undo
    x ^= (x << 15) & 0xEFC60000;

    // reverse x ^= (x << 7) & 0x9D2C5680;
    // to reverse, we need to build up the original value, using the unchanged 'xor 0' on the right
    // x    : 0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m o p q r s t u v w
    // x<<7 : 7 8 9 a b c d e f g h i j k l m o p q r s t u v w _ _ _ _ _ _ _
    // const: 1 0 0 1 1 1 0 1 0 0 1 0 1 1 0 0 0 1 0 1 0 1 1 0 1 0 0 0 0 0 0 0
    // x<7&c: 7 0 0 a b c 0 e 0 0 h 0 j k 0 0 0 p 0 r 0 t u 0 w 0 0 0 0 0 0 0
    // ------
    // x^x&c: 0'1 2 3'4'5'6 7'8 9 a'b c'd'e f g h'i j'k l'm'o p'q r s t u v w
    // r1   :                                     _ r _ t u _ w                 = 0x00001680 mask
    // x^r1 : 0'1 2 3'4'5'6 7'8 9 a'b c'd'e f g h'i j k l m o p q r s t u v
    // r2   :                       _ j k _ _ _ p _ _ _ _ _ _ _ _ _ _ _ _ _ _   = 0x000c4000 mask
    // x^r2 : 0'1 2 3'4'5'6 7'8 9 a'b c d e f g h i j k l m o p q r s t u v
    // r3   :         b c _ e _ _ h _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _   = 0x0d200000 mask
    // x^r3 : 0'1 2 3'4 5 6 7 8 9 a b c d e f g h i j k l m o p q r s t u v
    // r4   : 7 _ _ a _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _   = 0x90000000 mask
    // x^r4 : 0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m o p q r s t u v
    x ^= (x << 7) & 0x00001680;
    x ^= (x << 7) & 0x000c4000;
    x ^= (x << 7) & 0x0d200000;
    x ^= (x << 7) & 0x90000000;

    // reverse x ^= x >> 11;
    // x    : 0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m o p q r s t u v w
    // x>>11:                       0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k
    // x^x> : 0 1 2 3 4 5 6 7 8 9 a b'c'd'e'f'g'h'i'j'k'l'm'o'p'q'r's't'u'v'w
    // x'>11:                       0 1 2 3 4 5 6 7 8 9 a b'c'd'e'f'g'h'i'j'k'
    // x'^x>: 0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m"o"p"q"r"s"t"u"v"w"
    // x'>22:                                             0 1 2 3 4 5 6 7 8 9
    // x'^x>: 0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m o p q r s t u v w
    // There are 2 options, either use a masked x'>>11 to use only 0-a first, then repeat for missing m-w
    // or use the fact that " can be unmasked by doing an ^x'>>22. To check: m"=m'^b'=m^b^b^0=m^0
    x ^= x >> 11;
    x ^= x >> 22;
    x
}

pub fn clone(outputs: Vec<u32>) -> MersenneTwister {
    assert!(
        outputs.len() >= N,
        "We need at least N inputs to recover the state"
    );
    let mut state = [Wrapping(0); N];
    for i in 0..N {
        state[i] = Wrapping(untemper(outputs[i]));
    }

    MersenneTwister { state, index: N }
}

pub fn stream_cipher(data: &Vec<u8>, seed: u16) -> Vec<u8> {
    let mut keystream = Vec::new();
    let mut rng = MersenneTwister::new();
    rng.seed(seed as u32);
    for _ in 0..=data.len() / 4 {
        let next = rng.extract_number().expect("number");
        keystream.push(((next & 0xFF000000) >> 24) as u8);
        keystream.push(((next & 0x00FF0000) >> 16) as u8);
        keystream.push(((next & 0x0000FF00) >> 8) as u8);
        keystream.push((next & 0x000000FF) as u8);
    }
    data.iter().zip(keystream).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use rand::random;

    use super::*;

    #[test]
    fn rng_working_correctly() {
        let mut rng = MersenneTwister::new();
        rng.seed(1);
        debug_assert_eq!(rng.extract_number().unwrap(), 1791095845);
        debug_assert_eq!(rng.extract_number().unwrap(), 4282876139);
        debug_assert_eq!(rng.extract_number().unwrap(), 3093770124);
    }

    #[test]
    fn test_untemper() {
        let xs = vec![0xFFFFFFFF, 0x11111111, 0x12345678];
        for x in xs {
            let tempered = temper(x);
            let untempered = untemper(tempered);
            assert_eq!(untempered, x);
        }
    }

    #[test]
    #[ignore]
    fn bench_with_same_struct() {
        let start = SystemTime::now();
        let mut rng = MersenneTwister::new();
        for i in 1..10_000 {
            rng.seed(i);
            rng.extract_number().expect("number");
        }
        println!("Took {:?} seconds", start.elapsed().unwrap())
    }

    #[test]
    #[ignore]
    fn bench_with_new_struct() {
        let start = SystemTime::now();
        for _ in 1..10_000 {
            let mut rng = MersenneTwister::new();
            rng.seed(0);
            rng.extract_number().expect("number");
        }
        println!("Took {:?} seconds", start.elapsed().unwrap())
    }

    #[test]
    #[ignore]
    fn bench_with_single_seed() {
        let start = SystemTime::now();
        let mut rng = MersenneTwister::new();
        rng.seed(0);
        for _ in 1..10_000 {
            rng.extract_number().expect("number");
        }
        println!("Took {:?} seconds", start.elapsed().unwrap())
    }

    #[test]
    fn rng_as_streamcipher() {
        let text =
            b"This is some longer text to allow me to test the cipher for different lengths.";
        for i in 0..text.len() {
            let seed = random();
            assert_eq!(
                stream_cipher(&stream_cipher(&text[0..i].to_vec(), seed), seed),
                text[0..i].to_vec()
            );
        }
    }
}
