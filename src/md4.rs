//! # Implement SHA1, trying to proxy the std one first
//! learned: <<1 != rotate_left -> wrapping vs not

const STARTING_STATE: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, ]; // le

pub struct MyMd4 { h: [u32; 4] }

impl MyMd4 {
    /// Obtain only the padding for a certain input length.
    /// This code assumes, that len is the number of bytes and data is byte aligned.
    pub fn padding(len: usize) -> Vec<u8> {
        let mut padding = vec![0x80];
        let mut len_bits = len * 8;
        // might be off by one
        if len_bits % 512 > 448 {
            len_bits += 72;
            padding.append(&mut vec![0; 9]);
        }
        let zeros = 512 - (len_bits % 512) - 72;
        // println!("add {} zero bits: {}", zeros, zeros / 8);
        for _ in 0..zeros / 8 {
            padding.push(0 as u8);
        }
        padding.append(&mut ((len * 8) as u64).to_le_bytes().to_vec());
        padding
    }
    pub fn pad(mut input: Vec<u8>) -> Vec<u8> {
        input.append(&mut MyMd4::padding(input.len()));
        input
    }
    pub fn pad_fake_size(mut input: Vec<u8>, size: usize) -> Vec<u8> {
        input.append(&mut MyMd4::padding(input.len()));
        for _ in 0..8 {
            let _ = input.pop().unwrap();
        }
        let size = size * 8;
        input.append(&mut ((size) as u64).to_le_bytes().to_vec());
        input
    }

    /// Hash input vector, assumes padding has been applied already
    pub fn hash(input: Vec<u8>) -> [u32; 4] {
        MyMd4::hash_with_initial_state(STARTING_STATE, input)
    }

    /// Hash input vector with a specific starting state, assumes padding has been applied already
    pub fn hash_with_initial_state(state: [u32; 4], input: Vec<u8>) -> [u32; 4] {
        println!("input: {}", hex::encode(&input));
        assert_eq!(input.len() % (512 / 8), 0, "input length has to be a multiple of 512 bits");
        let mut sha1 = MyMd4 { h: state };
        for i in (0..input.len()).step_by(64) {
            let mut block: [u8; 64] = [0; 64];
            block.copy_from_slice(&input[i..i + 64]);
            do_block(&mut sha1, block);
        }
        sha1.h
    }

    /// Perform Sha1(key||data)
    pub fn keyed_mac(key: &Vec<u8>, data: &Vec<u8>) -> [u32; 4] {
        let mut input = key.clone();
        input.append(&mut data.clone());
        MyMd4::hash(MyMd4::pad(input))
    }

    /// validate that Sha1(key||data) == mac
    pub fn validate_mac(key: &Vec<u8>, data: &Vec<u8>, mac: &[u32; 4]) -> bool {
        let mut input = key.clone();
        input.append(&mut data.clone());
        MyMd4::hash(MyMd4::pad(input)) == *mac
    }
}

fn do_block(md4: &mut MyMd4, block: [u8; 64]) {
    fn f(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }

    fn g(x: u32, y: u32, z: u32) -> u32 { (x & y) | (x & z) | (y & z) }

    fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }


    fn round_1(a: &mut u32, b: u32, c: u32, d: u32, x_k: u32, s: u32) {
        *a = a.wrapping_add(f(b, c, d)).wrapping_add(x_k).rotate_left(s);
    }

    fn round_2(a: &mut u32, b: u32, c: u32, d: u32, x_k: u32, s: u32) {
        *a = a.wrapping_add(g(b, c, d)).wrapping_add(x_k).wrapping_add(0x5A827999).rotate_left(s);
    }

    fn round_3(a: &mut u32, b: u32, c: u32, d: u32, x_k: u32, s: u32) {
        *a = a.wrapping_add(h(b, c, d)).wrapping_add(x_k).wrapping_add(0x6ED9EBA1).rotate_left(s);
    }

    let mut x = [0u32; 16];

    for i in 0..16 {
        let mut s: [u8; 4] = [0; 4];
        s.copy_from_slice(&block[i * 4..i * 4 + 4]);
        x[i] = u32::from_le_bytes(s)
    }
    // fancy self written byte to u32 converter
    // for i in 0..64 {
    //     let tmp: u32 = (block[i] as u32).rotate_left(8 * (3 - i % 4) as u32);
    //     x[i / 4] = x[i / 4] | tmp;
    // }

    let mut a = md4.h[0];
    let mut b = md4.h[1];
    let mut c = md4.h[2];
    let mut d = md4.h[3];

    for &i in &[0, 4, 8, 12] {
        round_1(&mut a, b, c, d, x[i + 0], 3);
        round_1(&mut d, a, b, c, x[i + 1], 7);
        round_1(&mut c, d, a, b, x[i + 2], 11);
        round_1(&mut b, c, d, a, x[i + 3], 19);
    }
    // ass(a, 0xa299a540, "a".to_string());
    // ass(b, 0xefcdab89, "b".to_string());
    // ass(c, 0x98badcfe, "c".to_string());
    // ass(d, 0x10325476, "d".to_string());

    for i in 0..4 {
        round_2(&mut a, b, c, d, x[0 + i], 3);
        round_2(&mut d, a, b, c, x[4 + i], 5);
        round_2(&mut c, d, a, b, x[8 + i], 9);
        round_2(&mut b, c, d, a, x[12 + i], 13);
    }
    for &i in &[0, 2, 1, 3] {
        round_3(&mut a, b, c, d, x[0 + i], 3);
        round_3(&mut d, a, b, c, x[8 + i], 9);
        round_3(&mut c, d, a, b, x[4 + i], 11);
        round_3(&mut b, c, d, a, x[12 + i], 15);
    }

    md4.h[0] = md4.h[0].wrapping_add(a);
    md4.h[1] = md4.h[1].wrapping_add(b);
    md4.h[2] = md4.h[2].wrapping_add(c);
    md4.h[3] = md4.h[3].wrapping_add(d);
    // println!("{:x?}", sha1.h);
}

fn ass(is: u32, ex: u32, s: String) {
    println!("ex: {:0x?}", ex);
    println!("is: {:0x?}", is);
    assert_eq!(is, ex, "{}", s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md4_working_correctly() {
        let hash = MyMd4::hash(MyMd4::pad(b"abc".to_vec()));
        // let expected: [u32; 4] = [0xa448017a, 0xaf21d852, 0x5fc10ae8, 0x7aa6729d]; // le
        let expected: [u32; 4] = [0x7a0148a4, 0x52d821af, 0xe80ac15f, 0x9d72a67a];
        println!("ex: {:0x?}", expected);
        println!("is: {:0x?}", hash);
        assert_eq!(hash, expected);

        let hash = MyMd4::hash(MyMd4::pad(b"".to_vec()));
        // let expected: [u32; 4] = [0x31d6cfe0, 0xd16ae931, 0xb73c59d7, 0xe0c089c0]; // le
        let expected: [u32; 4] = [0xe0cfd631, 0x31e96ad1, 0xd7593cb7, 0xc089c0e0];
        println!("ex: {:0x?}", expected.to_vec());
        println!("is: {:0x?}", hash.to_vec());
        assert_eq!(hash, expected);
    }

    #[test]
    fn correct_padding() {
        let pad = MyMd4::padding(1);
        assert_eq!(pad[0], 0x80, "first padding byte");
        // don't really know why the padding is the wrong way around
        println!("{:?}", pad);
        assert_eq!(*pad.chunks_exact(8).last().unwrap().last().unwrap(), 8, "last padding byte");
        assert_eq!(pad.len(), 64 - 1, "length");

        // additional block necessary
        let pad = MyMd4::padding(57);
        assert_eq!(pad[0], 0x80, "first padding byte");
        assert_eq!(*pad.chunks_exact(8).last().unwrap().last().unwrap(), (57 * 8) as u8, "last padding byte");
        assert_eq!(pad.len(), 64 * 2 - 57, "length");
    }

    #[test]
    fn mac_not_obviously_broken() {
        let key = b"1234".to_vec();
        let data = b"data".to_vec();
        let mac = MyMd4::keyed_mac(&key, &data);
        assert!(MyMd4::validate_mac(&key, &data, &mac));
        assert!(!MyMd4::validate_mac(&b"123".to_vec(), &data, &mac));
        assert!(!MyMd4::validate_mac(&key, &b"new data".to_vec(), &mac));
    }
}
