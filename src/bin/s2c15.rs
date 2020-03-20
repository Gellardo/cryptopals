use cyptopals::unpad_pkcs7;

/// Strict pkcs7 unpadding
fn main() {
    unpad_pkcs7(vec![1; 3]).expect("No error");
    println!("{:?}", unpad_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04".to_vec()).expect("valid"));
    println!("{:?}", unpad_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05".to_vec()).expect_err("invalid"));
    println!("{:?}", unpad_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04".to_vec()).expect_err("invalid"));
}
