extern crate base64;
extern crate hex;

/// Solve Set 1 Challenge 1, converting between hex and b64.
fn main() {
    // convert between hex and base64
    let intermediate_hex = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    let intermediate_b64 = base64::decode("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t").unwrap();
    assert_eq!(intermediate_hex, intermediate_b64);
    println!("hex: {}", hex::encode(intermediate_hex));
    println!("b64: {}", base64::encode(&intermediate_b64));
    println!(":? : {:?}", &intermediate_b64);
}
