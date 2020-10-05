use crate::dh::{begin_dh_nist, gen_random};
use crate::sha1::MySha1;
use crate::srp::Messages::{Register, SRP1, SRP2, SRP3, SRP4};
use crate::u32_be_bytes;
use num_bigint::BigUint;
use std::ops::{Add, Rem};
use std::sync::mpsc::{Receiver, Sender};

#[derive(Debug)]
pub enum Messages<'a> {
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

pub fn n() -> BigUint {
    begin_dh_nist().p
    // BigUint::from(23u8)
}

fn hash_then_uint(inp: Vec<u8>) -> BigUint {
    vec_to_uint(u32_be_bytes(&MySha1::hash_padded(inp)))
}

pub fn server(tx: Sender<Messages>, rx: Receiver<Messages>) {
    let n = n();
    let g = BigUint::from(2u8);
    let k = BigUint::from(3u8);
    let salt = b"random prefix";
    let v = match rx.recv().unwrap() {
        Register { pass, .. } => {
            let x = hash_then_uint([salt.to_vec(), pass.to_vec()].concat());
            println!("s: x={:?}", x);
            let v = g.modpow(&x, &n);
            v
        }
        _ => panic!("never"),
    };

    let b = gen_random(&n);

    let a_pub = match rx.recv().unwrap() {
        SRP1 { a_pub, .. } => a_pub,
        _ => panic!("never"),
    };

    let b_pub = g.modpow(&b, &n);
    let b_pub = b_pub.add(&k * &v).rem(&n);
    tx.send(SRP2 {
        salt,
        b_pub: b_pub.clone(),
    })
    .unwrap();

    let u = hash_then_uint(uints_to_vec(&a_pub, &b_pub));
    let shared_s: BigUint = (a_pub * v.modpow(&u, &n)).modpow(&b, &n);
    println!("s: S={:?}", shared_s);
    let shared_k = MySha1::hash_padded(uint_to_vec(&shared_s));

    let hmac = match rx.recv().unwrap() {
        SRP3 { hmac } => hmac,
        _ => panic!("never"),
    };
    let s_hmac = MySha1::hmac(&u32_be_bytes(&shared_k), &salt.to_vec());
    println!("c: {:?} == {:?} : s", hmac, s_hmac);
    let auth = hmac == hmac;
    tx.send(SRP4 { auth }).unwrap();
}

pub fn client_ext(
    tx: Sender<Messages>,
    rx: Receiver<Messages>,
    a_source: &dyn Fn(&BigUint, &BigUint, &BigUint) -> BigUint,
    hmac_source: &dyn Fn(&[u8], &[u32]) -> [u32; 5],
) {
    let id = b"client";
    let pass = b"pass";
    tx.send(Register { id, pass }).unwrap();

    let n = n();
    let g = BigUint::from(2u8);
    let k = BigUint::from(3u8);
    let a = gen_random(&n);
    // let a_pub = g.modpow(&a, &n);
    let a_pub = a_source(&a, &g, &n);

    tx.send(SRP1 {
        id,
        a_pub: a_pub.clone(),
    })
    .unwrap();

    let (salt, b_pub) = match rx.recv().unwrap() {
        SRP2 { salt, b_pub } => (salt, b_pub),
        _ => panic!("never"),
    };

    let u = hash_then_uint(uints_to_vec(&a_pub, &b_pub));
    // let u = vec_to_uint(u32_be_bytes(&uH));
    let x = hash_then_uint([salt, pass].concat());
    println!("c: x={:?}", x);
    let shared_s: BigUint =
        (&b_pub + &n - (&k * g.modpow(&x, &n)).rem(&n)).modpow(&(a + u * x), &n);
    println!("c: S={:?}", shared_s);
    let shared_k = MySha1::hash_padded(uint_to_vec(&shared_s));

    let hmac1 = hmac_source(&salt, &shared_k);
    tx.send(SRP3 { hmac: hmac1 }).unwrap();
    match rx.recv().unwrap() {
        SRP4 { auth } => {
            if auth {
                println!("c: success")
            } else {
                println!("c: auth fail");
                panic!("the authentication failed")
            }
        }
        _ => panic!("never"),
    };
}

pub fn client(tx: Sender<Messages>, rx: Receiver<Messages>) {
    client_ext(tx, rx, &|a, g, n| g.modpow(a, n), &get_hmac)
}

pub fn get_hmac(salt: &[u8], shared_k: &[u32]) -> [u32; 5] {
    MySha1::hmac(&u32_be_bytes(&shared_k), &salt.to_vec())
}
