//! # Breadk SRP with different A values
//! let's try using 0, n, n*2 etc for A

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use num_bigint::BigUint;

use cyptopals::sha1::MySha1;
use cyptopals::srp::{client_ext, get_hmac, n, server, Messages};
use std::ops::Mul;

fn client_1(tx: Sender<Messages>, rx: Receiver<Messages>) {
    let a_source = |_: &BigUint, _: &BigUint, _: &BigUint| BigUint::from(0u8);
    let shared_k = MySha1::hash_padded(BigUint::from(0u8).to_bytes_be());
    let hmac_source = |s: &[u8], _: &[u32]| get_hmac(s, &shared_k);
    client_ext(tx, rx, &a_source, &hmac_source)
}

fn client_2(tx: Sender<Messages>, rx: Receiver<Messages>) {
    let a_source = |_: &BigUint, _: &BigUint, _: &BigUint| n();
    let shared_k = MySha1::hash_padded(BigUint::from(0u8).to_bytes_be());
    let hmac_source = |s: &[u8], _: &[u32]| get_hmac(s, &shared_k);
    client_ext(tx, rx, &a_source, &hmac_source)
}

fn client_3(tx: Sender<Messages>, rx: Receiver<Messages>) {
    let a_source = |_: &BigUint, _: &BigUint, _: &BigUint| n().mul(2u8);
    let shared_k = MySha1::hash_padded(BigUint::from(0u8).to_bytes_be());
    let hmac_source = |s: &[u8], _: &[u32]| get_hmac(s, &shared_k);
    client_ext(tx, rx, &a_source, &hmac_source)
}

fn main() {
    let (tx_alice, rx_alice): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let (tx_bot, rx_bot): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();

    let c = thread::spawn(|| client_1(tx_bot, rx_alice));
    let s = thread::spawn(|| server(tx_alice, rx_bot));
    c.join().expect("client finishes");
    s.join().expect("server finishes");

    let (tx_alice, rx_alice): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let (tx_bot, rx_bot): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let c = thread::spawn(|| client_2(tx_bot, rx_alice));
    let s = thread::spawn(|| server(tx_alice, rx_bot));
    c.join().expect("client finishes");
    s.join().expect("server finishes");

    let (tx_alice, rx_alice): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let (tx_bot, rx_bot): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let c = thread::spawn(|| client_3(tx_bot, rx_alice));
    let s = thread::spawn(|| server(tx_alice, rx_bot));
    c.join().expect("client finishes");
    s.join().expect("server finishes");
}
