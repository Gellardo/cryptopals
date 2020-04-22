//! # Implement SHA1, trying to proxy the std one first
use crypto::digest::Digest;
use crypto::sha1;

pub struct Sha1 { sha1: sha1::Sha1 }

impl Sha1 {
    pub fn new() -> Sha1 {
        Sha1 { sha1: sha1::Sha1::new() }
    }
}

impl Digest for Sha1 {
    fn input(&mut self, input: &[u8]) { self.sha1.input(input) }

    fn result(&mut self, out: &mut [u8]) { self.sha1.result(out) }

    fn reset(&mut self) { self.sha1.reset(); }

    fn output_bits(&self) -> usize { self.sha1.output_bits() }

    fn block_size(&self) -> usize { self.sha1.block_size() }
}

#[cfg(test)]
mod tests {
    use rand::random;

    use super::*;

    #[test]
    fn sha1_working_correctly() {
        let mut hash = Sha1::new();
        hash.input(&[]);

        assert_eq!(hash.result_str(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }
}
