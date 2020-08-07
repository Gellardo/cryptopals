//! # Implement SHA1, trying to proxy the std one first
//! learned: <<1 != rotate_left -> wrapping vs not

const STARTING_STATE: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

pub struct MySha1 { h: [u32; 5] }

impl MySha1 {
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
        println!("add {} zero bits: {}", zeros, zeros / 8);
        for _ in 0..zeros / 8 {
            padding.push(0 as u8);
        }
        padding.append(&mut ((len * 8) as u64).to_be_bytes().to_vec());
        padding
    }
    pub fn pad(mut input: Vec<u8>) -> Vec<u8> {
        input.append(&mut MySha1::padding(input.len()));
        input
    }

    /// Hash input vector, assumes padding has been applied already
    pub fn hash(input: Vec<u8>) -> [u32; 5] {
        MySha1::hash_with_initial_state(STARTING_STATE, input)
    }

    /// Hash input vector with a specific starting state, assumes padding has been applied already
    pub fn hash_with_initial_state(state: [u32; 5], input: Vec<u8>) -> [u32; 5] {
        assert_eq!(input.len() % (512 / 8), 0, "input length has to be a multiple of 512 bits");
        let mut sha1 = MySha1 { h: state };
        for i in (0..input.len()).step_by(64) {
            let mut block: [u8; 64] = [0; 64];
            block.copy_from_slice(&input[i..i + 64]);
            do_block(&mut sha1, block);
        }
        sha1.h
    }

    /// Perform Sha1(key||data)
    pub fn keyed_mac(key: &Vec<u8>, data: &Vec<u8>) -> [u32; 5] {
        let mut input = key.clone();
        input.append(&mut data.clone());

        MySha1::hash(input)
    }

    /// validate that Sha1(key||data) == mac
    pub fn validate_mac(key: &Vec<u8>, data: &Vec<u8>, mac: &[u32; 5]) -> bool {
        let mut input = key.clone();
        input.append(&mut data.clone());
        MySha1::hash(input) == *mac
    }
}

fn do_block(sha1: &mut MySha1, block: [u8; 64]) {
    let mut w = [0u32; 80];
    // fancy self written byte to u32 converter
    for i in 0..64 {
        let tmp: u32 = (block[i] as u32).rotate_left(8 * (3 - i % 4) as u32);
        w[i / 4] = w[i / 4] | tmp;
    }

    // prepare and expand
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    println!("{:x?}", block[0..64].to_vec());
    println!("{:x?}", w[0..16].to_vec());

    let mut a = sha1.h[0];
    let mut b = sha1.h[1];
    let mut c = sha1.h[2];
    let mut d = sha1.h[3];
    let mut e = sha1.h[4];

    for i in 0..80 {
        let mut f = 0;
        let mut k = 0;
        if i <= 19 {
            f = (b & c) | ((!b) & d);
            k = 0x5A827999;
            println!("f,k: {:0x} {:0x}", f, k)
        } else if 20 <= i && i <= 39 {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if 40 <= i && i <= 59 {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else if 60 <= i && i <= 79 {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        let tmp = (a.rotate_left(5)).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
        println!("{}: {:08x?} {:08x?} {:08x?} {:08x?} {:08x?}", i, a, b, c, d, e);

        // if i == 0 {
        //     assert_eq!([0x0116FC33, 0x67452301, 0x7BF36AE2, 0x98BADCFE, 0x10325476], [a, b, c, d, e])
        // } else if i == 10 {
        //     assert_eq!([0xFBDA9E89, 0x8351F929, 0x12DAB8CA, 0x27A301F5, 0x664F8C30], [a, b, c, d, e])
        // } else if i == 15 {
        //     assert_eq!([0x20BDD62F, 0x196BEE77, 0x644A3DA5, 0x1181ED99, 0x18C623F9], [a, b, c, d, e])
        // } else if i == 17 {
        //     assert_eq!([0x82AA6728, 0x4E925823, 0xC82F758B, 0xC65AFB9D, 0x644A3DA5], [a, b, c, d, e])
        // } else if i == 18 {
        //     assert_eq!([0xDC64901D, 0x82AA6728, 0xD3A49608, 0xC82F758B, 0xC65AFB9D], [a, b, c, d, e])
        // } else if i == 19 {
        //     assert_eq!([0xFD9E1D7D, 0xDC64901D, 0x20AA99CA, 0xD3A49608, 0xC82F758B], [a, b, c, d, e])
        // } else if i == 20 {
        //     assert_eq!([0x1A37B0CA, 0xFD9E1D7D, 0x77192407, 0x20AA99CA, 0xD3A49608], [a, b, c, d, e])
        // } else if i == 30 {
        //     assert_eq!([0x1267B407, 0xC5FBAF5D, 0xA0DC2D4B, 0xD2AA1365, 0x6F8D7EF5], [a, b, c, d, e])
        // } else if i == 50 {
        //     assert_eq!([0x641DB2CE, 0x120731C5, 0xEEBCE4CD, 0xAFAB40B2, 0x2806E11B], [a, b, c, d, e])
        // } else if i == 70 {
        //     assert_eq!([0xC199F8C7, 0x3F2588C2, 0x125C24F0, 0xDE37534A, 0x030F7CAD], [a, b, c, d, e])
        // }
    }

    sha1.h[0] = sha1.h[0].wrapping_add(a);
    sha1.h[1] = sha1.h[1].wrapping_add(b);
    sha1.h[2] = sha1.h[2].wrapping_add(c);
    sha1.h[3] = sha1.h[3].wrapping_add(d);
    sha1.h[4] = sha1.h[4].wrapping_add(e);
    println!("{:x?}", sha1.h);
}


// impl Digest for Sha1 {
//     fn input(&mut self, input: &[u8]) { self.sha1.input(input) }
//
//     fn result(&mut self, out: &mut [u8]) { self.sha1.result(out) }
//
//     fn reset(&mut self) { self.sha1.reset(); }
//
//     fn output_bits(&self) -> usize { self.sha1.output_bits() }
//
//     fn block_size(&self) -> usize { self.sha1.block_size() }
// }

/// Write a u32 into a vector, which must be 4 bytes long. The value is written in big-endian
/// format. (from crypto:cryptoutils
// pub fn write_u32_be(dst: &mut [u8], mut input: u32) {
//     assert!(dst.len() == 4);
//     input = input.to_be();
//     unsafe {
//         let tmp = &input as *const _ as *const u8;
//         ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 4);
//     }
// }
#[cfg(test)]
mod tests {
    use crypto::digest::Digest;
    use crypto::sha1::Sha1;

    use super::*;

    #[test]
    fn sha1_working_correctly() {
        let hash = MySha1::hash(MySha1::pad(b"abc".to_vec()));
        let expected = [0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d];
        println!("ex: {:0x?}", expected);
        println!("is: {:0x?}", hash);
        assert_eq!(hash, expected);

        let hash = MySha1::hash(MySha1::pad(b"".to_vec()));
        let expected: [u32; 5] = [0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709];
        println!("ex: {:0x?}", expected.to_vec());
        println!("is: {:0x?}", hash.to_vec());
        assert_eq!(hash, expected);
    }

    #[test]
    fn correct_padding() {
        let pad = MySha1::padding(1);
        assert_eq!(pad[0], 0x80, "first padding byte");
        assert_eq!(*pad.last().unwrap(), 8, "last padding byte");
        assert_eq!(pad.len(), 64 - 1, "length");

        // additional block necessary
        let pad = MySha1::padding(57);
        assert_eq!(pad[0], 0x80, "first padding byte");
        assert_eq!(*pad.last().unwrap(), (57 * 8) as u8, "last padding byte");
        assert_eq!(pad.len(), 64 * 2 - 57, "length");
    }
}
