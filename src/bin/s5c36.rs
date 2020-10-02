//! # Implement SRP
//! Supposedly DH with a tweak to mix in password and not store something crackable on server.

use cyptopals::srp::{client, server, Messages};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

fn main() {
    let (tx_alice, rx_alice): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();
    let (tx_bot, rx_bot): (Sender<Messages>, Receiver<Messages>) = mpsc::channel();

    let client = thread::spawn(|| client(tx_bot, rx_alice));
    let server = thread::spawn(|| server(tx_alice, rx_bot));
    client.join().expect("client finishes");
    server.join().expect("server finishes");
}
