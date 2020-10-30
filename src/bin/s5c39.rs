//! # Implement RSA
//! learning: p and q can't be 7 because et is not coprime(?) with 3
//! (and non-abvious testing if there is no intuition why the invmod fails on div by null)

use cyptopals::rsa;

fn main() {
    let (priv_key, pub_key) = rsa::generate_key(24).expect("Did not find a keypair");
    let plain = b"as";
    let cipher = pub_key.encrypt(&plain.to_vec());
    assert_eq!(priv_key.decrypt(&cipher), plain);
}

#[cfg(test)]
mod test {
    use super::main;

    #[test]
    fn it_works() {
        main()
    }
}
