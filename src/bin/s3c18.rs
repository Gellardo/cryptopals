/// # CTR
use cyptopals::aes_ctr;

fn main() {
    let cipher = base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==").unwrap();
    let decrypted = aes_ctr(&cipher, &b"YELLOW SUBMARINE".to_vec(), 0);
    println!("{:?}", String::from_utf8(decrypted.clone()).unwrap());
    println!("cipher length: {}, plain length: {}", cipher.len(), decrypted.len());
}
