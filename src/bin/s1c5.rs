use cyptopals::xor_repeating_key;

/// Implement repeating key xor
fn main() {
    let plain = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
    let key = b"ICE".to_vec();

    let cipher = xor_repeating_key(plain, key);

    let expected = hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
    assert_eq!(cipher, expected)
}
