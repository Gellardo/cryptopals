use cyptopals::{xor_single_byte, rate_plain, Score};

/// Decipher text encrypted with a single byte xor
fn main() {
    let cipher = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
    let mut possible_best: Vec<(Score, u8, Vec<u8>)> = Vec::new();
    for key in 0..255u8 {
        let guess = xor_single_byte(cipher.clone(), key);
        let rating = rate_plain(&guess);
        possible_best.push((rating, key, guess));
    }

    println!("{} keys tried, best 3:", possible_best.len());
    possible_best.sort();
    for i in possible_best.len() - 3..possible_best.len() {
        let (rating, key, guess) = possible_best.get(i).unwrap();
        let guess_str = String::from_utf8(guess.clone());
        println!("{:?},{}: {:?}", *key as char, rating, guess_str)
    }
}
