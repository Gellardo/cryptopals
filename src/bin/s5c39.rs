//! # Implement RSA
//! learning: p and q can't be 7 because et is not coprime(?) with 3
//! (and non-abvious testing if there is no intuition why the invmod fails on div by null)

use cyptopals::rsa;

fn main() {
    rsa::generate_key();
}

#[cfg(test)]
mod test {
    use super::main;

    #[test]
    fn it_works() {
        main()
    }
}
