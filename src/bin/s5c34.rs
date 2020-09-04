//! # Implement DH MITM key fixing

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, RecvError, Sender};
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

fn encrypt(plain: Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    aes_cbc_encrypt(&pad_pkcs7(plain, 16), key, iv)
}

fn decrypt(cipher: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    unpad_pkcs7(aes_cbc_decrypt(cipher, key, iv)).expect("no evil ppl here")
}

fn main() {
    let (tx_alice, rx_alice): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let (tx_bot, rx_bot): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();

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
        let secret = MySha1::hash(secret.to_bytes_be());
        let secret = u32_be_bytes(&secret[0..4]);
        println!("alice secret = {:?}", secret);

        let iv = random_128_bit();
        let cipher = encrypt(b"alice message".to_vec(), &secret, &iv);
        tx.send(EncryptedMessage { cipher, iv });

        let message = match rx.recv().unwrap() {
            Messages::EncryptedMessage { cipher, iv } => {
                let plain = decrypt(&cipher, &secret, &iv);
                println!("a<-: {:?}", plain);
                plain
            }
            _ => panic!("oh no encrypted bot"),
        };
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
        let secret = MySha1::hash(secret.to_bytes_be());
        let secret = u32_be_bytes(&secret[0..4]);
        println!("bot secret = {:?}", secret);

        tx.send(DhFinish { b_pub }).unwrap();

        let message = match rx.recv().unwrap() {
            Messages::EncryptedMessage { cipher, iv } => {
                let plain = decrypt(&cipher, &secret, &iv);
                println!("b<- : {:?}", plain);
                plain
            }
            _ => panic!("oh no encrypted alice"),
        };

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
}
