//! # Implement SRP
//! Supposedly DH with a tweak to mix in password and not store something crackable on server.

use std::ops::{Add, Rem, Sub};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use num_bigint::BigUint;

use cyptopals::dh::{begin_dh, begin_dh_nist, gen_random};
use cyptopals::sha1::MySha1;
use cyptopals::{random_128_bit, u32_be_bytes};

use crate::Messages::{Register, SRP1, SRP2, SRP3, SRP4};

#[derive(Debug)]
enum Messages<'a> {
    Register { id: &'a [u8], pass: &'a [u8] },
    SRP1 { id: &'a [u8], a_pub: BigUint },
    SRP2 { salt: &'a [u8], b_pub: BigUint },
    SRP3 { hmac: [u32; 5] },
    SRP4 { auth: bool },
}

fn vec_to_uint(inp: Vec<u8>) -> BigUint {
    let hash = MySha1::hash(MySha1::pad(inp));
    BigUint::from_bytes_be(&u32_be_bytes(&hash))
}

fn uint_to_vec(inp: &BigUint) -> Vec<u8> {
    inp.to_bytes_be()
}

fn uints_to_vec(inp: &BigUint, inp2: &BigUint) -> Vec<u8> {
    [uint_to_vec(inp), uint_to_vec(inp2)].concat()
}

fn n() -> BigUint {
    begin_dh_nist().p
    // BigUint::from(23u8)
}

fn main() {
    let (tx_alice, rx_alice): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let (tx_bot, rx_bot): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();

    let server = move || {
        let tx = tx_alice;
        let rx = rx_bot;

        let n = n();
        let g = BigUint::from(2u8);
        let k = BigUint::from(3u8);
        let salt = b"random prefix";
        let v = match rx.recv().unwrap() {
            Register { id, pass } => {
                let x = vec_to_uint(u32_be_bytes(&MySha1::hash_padded(
                    [salt.to_vec(), pass.to_vec()].concat(),
                )));
                println!("s: x={:?}", x);
                let v = g.modpow(&x, &n);
                v
            }
            _ => panic!("never"),
        };

        let b = gen_random(&n);

        let (id, a_pub) = match rx.recv().unwrap() {
            SRP1 { id, a_pub } => (id, a_pub),
            _ => panic!("never"),
        };

        let b_pub = g.modpow(&b, &n);
        let b_pub = b_pub.add(&k * &v).rem(&n);
        tx.send(SRP2 {
            salt,
            b_pub: b_pub.clone(),
        })
        .unwrap();

        let uH = MySha1::hash_padded(uints_to_vec(&a_pub, &b_pub));
        let u = vec_to_uint(u32_be_bytes(&uH));
        let shared_s: BigUint = (a_pub * v.modpow(&u, &n)).modpow(&b, &n);
        println!("s: S={:?}", shared_s);
        let shared_k = MySha1::hash_padded(uint_to_vec(&shared_s));

        let (hmac) = match rx.recv().unwrap() {
            SRP3 { hmac } => (hmac),
            _ => panic!("never"),
        };
        let auth = MySha1::hmac(&u32_be_bytes(&shared_k), &salt.to_vec()) == hmac;
        tx.send(SRP4 { auth }).unwrap();
    };

    let client = move || {
        let tx = tx_bot;
        let rx = rx_alice;

        let id = b"client";
        let pass = b"pass";
        tx.send(Register { id, pass }).unwrap();

        let n = n();
        let g = BigUint::from(2u8);
        let k = BigUint::from(3u8);
        let a = gen_random(&n);
        let a_pub = g.modpow(&a, &n);

        tx.send(SRP1 {
            id,
            a_pub: a_pub.clone(),
        })
        .unwrap();

        let (salt, b_pub) = match rx.recv().unwrap() {
            SRP2 { salt, b_pub } => (salt, b_pub),
            _ => panic!("never"),
        };

        let uH = MySha1::hash_padded(uints_to_vec(&a_pub, &b_pub));
        let u = vec_to_uint(u32_be_bytes(&uH));
        let xH = MySha1::hash_padded([salt, pass].concat());
        let x = vec_to_uint(u32_be_bytes(&xH));
        println!("c: x={:?}", x);
        let shared_s: BigUint =
            (&b_pub + &n - (&k * g.modpow(&x, &n)).rem(&n)).modpow(&(a + u * x), &n);
        println!("c: S={:?}", shared_s);
        let shared_k = MySha1::hash_padded(uint_to_vec(&shared_s));

        tx.send(SRP3 {
            hmac: MySha1::hmac(&u32_be_bytes(&shared_k), &salt.to_vec()),
        })
        .unwrap();
        match rx.recv().unwrap() {
            SRP4 { auth } => {
                if auth {
                    println!("c: success")
                } else {
                    println!("c: auth fail")
                }
            }
            _ => panic!("never"),
        };
    };
    let client = thread::spawn(client);
    let server = thread::spawn(server);
    client.join().expect("client finishes");
    server.join().expect("server finishes");
}
