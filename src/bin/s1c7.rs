extern crate crypto;

use std::fs;

use crypto::{aes, blockmodes, buffer};
use crypto::aes::KeySize::KeySize128;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};

/// Decrypt AES ECB
///
/// Nice to know: `openssl enc -d -aes-128-ecb -K '59454c4c4f57205355424d4152494e45' -a -in files/aes_ecb.txt`
/// *Can't* use `YELLOW SUBMARINE` since 1) `-k` seems to hash it 2) `-K` expects hex, therefore `hexdump -C` FTW
fn main() {
    let line = fs::read_to_string("./files/aes_ecb.txt").unwrap();
    let cipher = base64::decode(&line.replace("\n", "")).unwrap();

//    let plain = aes_ecb(cipher, "YELLOW SUBMARINE");
    let mut decryptor = aes::ecb_decryptor(KeySize128, b"YELLOW SUBMARINE", blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(cipher.as_slice());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    println!("{:?}", String::from_utf8(final_result))
}
