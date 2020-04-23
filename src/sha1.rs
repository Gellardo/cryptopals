//! # Implement SHA1, trying to proxy the std one first
use std::mem;

use crypto::digest::Digest;
use crypto::sha1;

/// from crypto::sha1::Sha1
pub struct HackSha1 {
    h: [u32; 5],
    _length_bits: u64,
    _buffer: FixedBuffer64,
    _computed: bool,
}

struct FixedBuffer64 {
    _buffer: [u8; 64],
    _buffer_idx: usize,
}

pub struct Sha1 { sha1: sha1::Sha1 }

impl Sha1 {
    pub fn new() -> Sha1 {
        Sha1 { sha1: sha1::Sha1::new() }
    }

    /// Based on assumptions about the rust crypto implementation, we can get access to the underlying state
    /// Prone to breaking if [sha1::Sha1] struct changes
    pub fn new_with_state(state: [u32; 5]) -> Sha1 {
        let sha1 = sha1::Sha1::new();
        // this works as long as the underlying structure does not change
        // otherwise i expect this to break horribly
        let mut hacked: HackSha1 = unsafe { mem::transmute(sha1) };
        hacked.h = state;
        let sha1_changed = unsafe { mem::transmute(hacked) };
        Sha1 { sha1: sha1_changed }
    }

    /// Based on assumptions about the rust crypto implementation, we can get access to the state
    pub fn get_state(&mut self) -> [u32; 5] {
        // this works as long as the underlying structure does not change
        // otherwise i expect this to break horribly
        let hacked: HackSha1 = unsafe { mem::transmute(self.sha1) };
        hacked.h
    }
}


impl Digest for Sha1 {
    fn input(&mut self, input: &[u8]) { self.sha1.input(input) }

    fn result(&mut self, out: &mut [u8]) { self.sha1.result(out) }

    fn reset(&mut self) { self.sha1.reset(); }

    fn output_bits(&self) -> usize { self.sha1.output_bits() }

    fn block_size(&self) -> usize { self.sha1.block_size() }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_working_correctly() {
        let mut hash = Sha1::new();
        hash.input(&[]);

        assert_eq!(hash.result_str(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha1_unsafe_code_not_obviously_broken() {
        let mut hash_hacked = Sha1::new_with_state([0, 1, 2, 3, 4]);
        assert_eq!(hash_hacked.get_state(), [0, 1, 2, 3, 4]);
        hash_hacked.input(&[2; 50]);
        assert_eq!(hash_hacked.result_str(),
                   "c3076928b640fff2b352d65a7b3c380170baffe7", // calculated correctly
                   "changed the whole state, depends on sha1::Sha1 memory layout, \
                       error means the HackedSha1 struct should be checked");

        //using the default values should produce the one for the empty string
        let default_start_state = [ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        let mut hash_hacked = Sha1::new_with_state(default_start_state);
        assert_eq!(hash_hacked.result_str(), "da39a3ee5e6b4b0d3255bfef95601890afd80709", "using default state");
    }

    #[test]
    fn correct_padding() {
        let pad = padding(1);
        assert_eq!(pad[0], 0x80, "first padding byte");
        assert_eq!(*pad.last().unwrap(), 8, "last padding byte");
        assert_eq!(pad.len(), 64 - 1, "length");

        // additional block necessary
        let pad = padding(57);
        assert_eq!(pad[0], 0x80, "first padding byte");
        assert_eq!(*pad.last().unwrap(), (57 * 8) as u8, "last padding byte");
        assert_eq!(pad.len(), 64 * 2 - 57, "length");
    }
}
