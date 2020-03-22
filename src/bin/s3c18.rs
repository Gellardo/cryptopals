/// # CTR
use cyptopals::ctr_keystream;

fn main() {
    let cipher = base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==").unwrap();
    let decrypted: Vec<u8> = cipher.iter()
        .zip(ctr_keystream(&b"YELLOW SUBMARINE".to_vec(), cipher.len()))
        .map(|(x, y)| x ^ y)
        .collect();
    println!("{:?}", String::from_utf8(decrypted.clone()).unwrap());
    println!("cipher length: {}, plain length: {}", cipher.len(), decrypted.len());
}
