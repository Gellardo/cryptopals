use cyptopals::xor;

/// Simple XOR of 2 byte 'strings'
fn main() {
    let s1 = "1c0111001f010100061a024b53535009181c";
    let s2 = "686974207468652062756c6c277320657965";
    let result = "746865206b696420646f6e277420706c6179";
    assert_eq!(xor(hex::decode(s1).unwrap(),
                   hex::decode(s2).unwrap()),
               hex::decode(result).unwrap())
}
