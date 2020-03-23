/// # Decrypt CTR with static nonce
/// Basically reuse our breaking of single byte xor:
/// every i_th byte of all cipher texts is xor'd with the same keystream byte == single byte xor.
/// The decryption gets worse the less ciphers there are for that position, but it is good enough.
/// Improvements would be exploiting the statistics of the english language more.
/// But the challenge says, this is the inferior solution, so lets just move on.
use cyptopals::{aes_ctr, break_xor_single_byte, random_128_bit};

fn get_ciphers() -> Vec<Vec<u8>> {
    let plains = vec![
        base64::decode("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==").unwrap(),
        base64::decode("Q29taW5nIHdpdGggdml2aWQgZmFjZXM=").unwrap(),
        base64::decode("RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==").unwrap(),
        base64::decode("RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=").unwrap(),
        base64::decode("SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk").unwrap(),
        base64::decode("T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==").unwrap(),
        base64::decode("T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=").unwrap(),
        base64::decode("UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==").unwrap(),
        base64::decode("QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=").unwrap(),
        base64::decode("T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl").unwrap(),
        base64::decode("VG8gcGxlYXNlIGEgY29tcGFuaW9u").unwrap(),
        base64::decode("QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==").unwrap(),
        base64::decode("QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=").unwrap(),
        base64::decode("QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==").unwrap(),
        base64::decode("QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=").unwrap(),
        base64::decode("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=").unwrap(),
        base64::decode("VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==").unwrap(),
        base64::decode("SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==").unwrap(),
        base64::decode("SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==").unwrap(),
        base64::decode("VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==").unwrap(),
        base64::decode("V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==").unwrap(),
        base64::decode("V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==").unwrap(),
        base64::decode("U2hlIHJvZGUgdG8gaGFycmllcnM/").unwrap(),
        base64::decode("VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=").unwrap(),
        base64::decode("QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=").unwrap(),
        base64::decode("VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=").unwrap(),
        base64::decode("V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=").unwrap(),
        base64::decode("SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==").unwrap(),
        base64::decode("U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==").unwrap(),
        base64::decode("U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=").unwrap(),
        base64::decode("VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==").unwrap(),
        base64::decode("QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu").unwrap(),
        base64::decode("SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=").unwrap(),
        base64::decode("VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs").unwrap(),
        base64::decode("WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=").unwrap(),
        base64::decode("SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0").unwrap(),
        base64::decode("SW4gdGhlIGNhc3VhbCBjb21lZHk7").unwrap(),
        base64::decode("SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=").unwrap(),
        base64::decode("VHJhbnNmb3JtZWQgdXR0ZXJseTo=").unwrap(),
        base64::decode("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=").unwrap(),
    ];

    let key = random_128_bit();
    let ciphers = plains.iter().map(|p| aes_ctr(p, &key, 0)).collect();
    ciphers
}

fn main() {
    let ciphers = get_ciphers();
    let mut keystream = Vec::new();
    for i in 0..64 {
        let cipher = ciphers.iter().flat_map(|c| c.get(i)).map(|c| *c).collect();
        let options = break_xor_single_byte(cipher);
        let (_, key, _) = options.get(0).unwrap();
        keystream.push(key.to_owned());
    }

    for i in 0..10 {
        let decrypted = ciphers.get(i).unwrap().iter()
            .zip(keystream.iter())
            .map(|(x, &y)| (x ^ y) as char)
            .collect::<String>();
        println!("{}: {}",i, decrypted);
    }
}
