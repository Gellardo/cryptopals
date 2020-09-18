//! # Implement DH MITM key fixing
//! Basically, put malroy into the middle, and let him do 2 DH exchanges:
//! One with A and one with B, both yielding a secret key for that segment of the transmission
//!
//! Now he only has to act as a proxy:
//! 1. decrypt the messages with the correct key when receiving
//! 2. re-encrypt them with the other key before forwarding them to the other side.
//!
//! Or read the challenge correctly and replace A/B in the messages with p.
//! That results in the following computation for the shared secret value:
//! ```
//! A^b % p = p^b % p = 0
//! B^a % p = p^a % p = 0
//! ```
//! Therefore the generated secret Key will always be the same value.

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use num_bigint::BigUint;

use cyptopals::dh::{begin_dh, begin_dh_nist};
use cyptopals::sha1::MySha1;
use cyptopals::{
    aes_cbc_decrypt, aes_cbc_encrypt, pad_pkcs7, random_128_bit, u32_be_bytes, unpad_pkcs7,
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

fn decrypt(cipher: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    unpad_pkcs7(aes_cbc_decrypt(cipher, key, iv)).expect("no evil ppl here")
}

fn main() {
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
            Messages::DhSetup {
                p,
                g,
                a_pub: _a_pub,
            } => begin_dh(p, g),
            _ => panic!("never"),
        };
        tx_m_bot
            .send(DhSetup {
                p: dh.p.clone(),
                g: dh.g.clone(),
                a_pub: dh.p.clone(),
            })
            .unwrap();
        tx_m_alice
            .send(DhFinish {
                b_pub: dh.p.clone(),
            })
            .unwrap();

        // result for alice and bot will always be 0
        let s = gen_key(BigUint::from(0u8));
        println!("mallroy secret = {:?}", s);

        match rx_m_alice.recv().unwrap() {
            DhFinish { b_pub } => dh.gen_shared(&b_pub),
            _ => panic!("never"),
        };
        //DH finished

        let message_alice = match rx_m_bot.recv().unwrap() {
            Messages::EncryptedMessage { cipher, iv } => {
                let plain = decrypt(&cipher, &s, &iv);
                plain
            }
            _ => panic!("never"),
        };
        println!("m<-: {:?} (a->b)", message_alice);
        let iv = random_128_bit();
        tx_m_bot
            .send(EncryptedMessage {
                cipher: encrypt(message_alice, &s, &iv),
                iv,
            })
            .unwrap();

        let message_bot = match rx_m_alice.recv().unwrap() {
            Messages::EncryptedMessage { cipher, iv } => {
                let plain = decrypt(&cipher, &s, &iv);
                plain
            }
            _ => panic!("never"),
        };
        println!("m<-: {:?} (b->a)", message_bot);
        let iv = random_128_bit();
        tx_m_alice
            .send(EncryptedMessage {
                cipher: encrypt(message_bot, &s, &iv),
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
