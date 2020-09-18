//! # Implement DH MITM with malicious g param
//! Similar to the previous challenge, but this time replace `g` instead of `A`/`B`.
//! Also needs slightly different protocol that sends over DH params first.
//! Though I do not see, why the additional ACK would be necessary before alice sends `A`, so I'll reuse the old one.
//!
//! Try out;
//! - `g = 1` and `g = p` should result in some static key
//! - `g = p - 1`: Exponentiation result oscillate between `1` and `p - 1`, so only 2 keys to try
//!
//! Well not as easy, since we can only override g for bot.
//! So we need to muck around with `A` too, and in the complicated case might even need to reencrypt
//! But we should be fine only manipulating messages in one direction instead of both.

use std::ops::Sub;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use num_bigint::BigUint;

use cyptopals::dh::{begin_dh, begin_dh_nist};
use cyptopals::sha1::MySha1;
use cyptopals::{
    aes_cbc_decrypt, aes_cbc_encrypt, pad_pkcs7, random_128_bit, u32_be_bytes, unpad_pkcs7,
    CryptoError,
};

use crate::Messages::{DhFinish, DhSetup, EncryptedMessage};

#[derive(Debug)]
enum Messages {
    DhSetup {
        p: BigUint,
        g: BigUint,
        a_pub: BigUint,
    },
    DhFinish {
        b_pub: BigUint,
    },
    EncryptedMessage {
        cipher: Vec<u8>,
        iv: Vec<u8>,
    },
}

fn gen_key(value: BigUint) -> Vec<u8> {
    u32_be_bytes(&MySha1::hash(MySha1::pad(value.to_bytes_be()))[0..4])
}

fn encrypt(plain: Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    aes_cbc_encrypt(&pad_pkcs7(plain, 16), key, iv)
}

fn decrypt_unsafe(cipher: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    unpad_pkcs7(aes_cbc_decrypt(cipher, key, iv))
}

fn decrypt(cipher: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    decrypt_unsafe(cipher, key, iv).expect("no evil ppl here")
}

fn run_with_g(
    m_g: BigUint,
    m_pub: BigUint,
    secrets: &'static (dyn Fn(&BigUint, &(Vec<u8>, Vec<u8>)) -> (BigUint, BigUint)
                  + Sync
                  + 'static),
) {
    let (tx_alice, rx_alice): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let (tx_bot, rx_bot): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();

    // Setup Malroy in the middle
    // a -> tx_bot -> rx_bot -> b
    // a <- rx_alice <- tx_alice <- b
    let (tx_m_alice, rx_m_alice): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let (tx_m_bot, rx_m_bot): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    // rewire(/-name) receiving ends so that the new m-channels are put into the second half
    // a -> tx_bot -> rx_m_bot -> m -> tx_m_bot -(new channel)-> rx_bot -> b
    // a <- rx_alice <-(new channel)- tx_m_alice <- rx_m_alice <- tx_alice <- b
    let (rx_bot, rx_m_bot) = (rx_m_bot, rx_bot);
    let (rx_alice, rx_m_alice) = (rx_m_alice, rx_alice);

    let malroy = thread::spawn(move || {
        let dh = match rx_m_bot.recv().unwrap() {
            Messages::DhSetup { p, g, a_pub: _ } => begin_dh(p, g),
            _ => panic!("never"),
        };
        tx_m_bot
            .send(DhSetup {
                p: dh.p.clone(),
                g: m_g,
                a_pub: m_pub,
            })
            .unwrap();
        let b_pub = match rx_m_alice.recv().unwrap() {
            DhFinish { b_pub } => b_pub,
            _ => panic!("never"),
        };
        tx_m_alice
            .send(DhFinish {
                b_pub: b_pub.clone(),
            })
            .unwrap();
        //DH finished

        let cipher_alice = match rx_m_bot.recv().unwrap() {
            Messages::EncryptedMessage { cipher, iv } => (cipher, iv),
            _ => panic!("never"),
        };

        let (s_a, s_b) = secrets(&b_pub, &cipher_alice);
        let (s_a, s_b) = (gen_key(s_a), gen_key(s_b));
        let message_alice = decrypt(&cipher_alice.0, &s_a, &cipher_alice.1);
        println!("mallroy secrets = {:?}, {:?}", s_a, s_b);

        println!("m<-: {:?} (a->b)", message_alice);
        let iv = random_128_bit();
        tx_m_bot
            .send(EncryptedMessage {
                cipher: encrypt(message_alice, &s_b, &iv),
                iv,
            })
            .unwrap();

        let message_bot = match rx_m_alice.recv().unwrap() {
            Messages::EncryptedMessage { cipher, iv } => {
                let plain = decrypt(&cipher, &s_b, &iv);
                plain
            }
            _ => panic!("never"),
        };
        println!("m<-: {:?} (b->a)", message_bot);
        let iv = random_128_bit();
        tx_m_alice
            .send(EncryptedMessage {
                cipher: encrypt(message_bot, &s_a, &iv),
                iv,
            })
            .unwrap();
    });

    let alice = thread::spawn(move || {
        let tx = tx_bot;
        let rx = rx_alice;

        let dh = begin_dh_nist();
        tx.send(DhSetup {
            p: dh.p.clone(),
            g: dh.g.clone(),
            a_pub: dh.gen_pub(),
        })
        .unwrap();

        let secret = match rx.recv().unwrap() {
            Messages::DhFinish { b_pub } => dh.gen_shared(&b_pub),
            _ => panic!("oh no dh bot"),
        };
        let secret = gen_key(secret);
        println!("alice secret = {:?}", secret);

        let iv = random_128_bit();
        let cipher = encrypt(b"alice message".to_vec(), &secret, &iv);
        tx.send(EncryptedMessage { cipher, iv }).unwrap();

        let message = match rx.recv().unwrap() {
            Messages::EncryptedMessage { cipher, iv } => decrypt(&cipher, &secret, &iv),
            _ => panic!("oh no encrypted bot"),
        };
        println!("a<-: {:?}", message);
        println!("alice finished");
    });

    let bot = thread::spawn(move || {
        let tx = tx_alice;
        let rx = rx_bot;
        let (b_pub, secret) = match rx.recv().unwrap() {
            Messages::DhSetup { p, g, a_pub } => {
                let dh = begin_dh(p, g);
                (dh.gen_pub(), dh.gen_shared(&a_pub))
            }
            _ => panic!("oh no dh alice"),
        };
        let secret = gen_key(secret);
        println!("bot secret = {:?}", secret);

        tx.send(DhFinish { b_pub }).unwrap();

        let message = match rx.recv().unwrap() {
            Messages::EncryptedMessage { cipher, iv } => decrypt(&cipher, &secret, &iv),
            _ => panic!("oh no encrypted alice"),
        };
        println!("b<-: {:?}", message);

        let iv = random_128_bit();
        tx.send(EncryptedMessage {
            cipher: encrypt(message, &secret, &iv),
            iv,
        })
        .unwrap();
        println!("bot finished");
    });
    alice.join().expect("alice finishes");
    bot.join().expect("bot finishes");
    malroy.join().expect("malroy finishes")
}

fn main() {
    println!("g=1");
    // s_a = B ^ a % p = 1^b^a %p = 1
    // s_b = A ^ b % p = g^a^b %p = ? -> need to fuck with A==set to 1?
    run_with_g(BigUint::from(1u8), BigUint::from(1u8), &|_, _| {
        (BigUint::from(1u8), BigUint::from(1u8))
    });

    println!("g=p");
    // s_a = B ^ a % p = p^b^a %p = 0
    // s_b = A ^ b % p = g^a^b %p = ? -> need to fuck with A==set to 0
    run_with_g(begin_dh_nist().p, BigUint::from(0u8), &|_, _| {
        (BigUint::from(0u8), BigUint::from(0u8))
    });

    println!("g=p-1");
    // s_a = B ^ a % p = (p-1)^b^a %p = 1 | p-1
    // s_b = A ^ b % p = g^a^b %p = ? -> need to fuck with A==set to p-1, then b_shared = (p-1)^b %p = b_pub
    run_with_g(
        begin_dh_nist().p.sub(1u8),
        begin_dh_nist().p.sub(1u8),
        &|b_pub, cipher_a| {
            let s_a = decrypt_unsafe(&cipher_a.0, &gen_key(BigUint::from(1u8)), &cipher_a.1)
                .map(|_| BigUint::from(1u8))
                .unwrap_or_else(|_| begin_dh_nist().p.sub(1u8));
            (s_a, b_pub.clone())
        },
    );
}
