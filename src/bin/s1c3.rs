use cyptopals::break_xor_single_byte;

/// Decipher text encrypted with a single byte xor
fn main() {
    let cipher =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();
    let possible_best = break_xor_single_byte(cipher);

    for (rating, key, guess) in possible_best {
        let guess_str = String::from_utf8(guess.clone());
        println!("{:?},{}: {:?}", key as char, rating, guess_str)
    }
}
