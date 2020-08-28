//! # Brutally slightly better hash validation - smaller timing leak
//! use an insecure compare, that adds 5ms per character and returns early
//!
//! ## How to go about this
//! Basically, I want do the same thing as before.
//! But also repeat the measurements to try and remove the noise caused by the rest of the machine.
//!
//! Sidenote: I am very happy that I brought down the runtime for the previous challenge.
//! Waiting 40 min to find out if a certain implementation works would be awful.
//! (Well not 40 min since the sleep has been reduced by 10x, but you know what I mean)
//!
//! ## Obeservations about timings
//! 1. If you do the same value 3 times in a row before going to the next one, the influence of the machine is not spread enough.
//!    Usually, slowdown occurs over some period of time, if all 3 measurements fall into it, the noise is always equally in there.
//!    Therefore I use `0..256,0..256,0..256` instead of `0,0,0,1,1,1,...,256,256,256`
//! 2. For similar reasons, just taking the minimum duration does not really work.
//!    If the slower better match has less contention than a faster worse match, the slowest of the latter can still be slower than the better match.
//! 3. parallelism makes it worse... solution that was successful with no parallelism failed before pos 10
//! 4. If at first you don't succeed, throw a few more probes/repetitions at it.
//! 5. Points 1 & 3 are no longer relevant if you do point 4 enough
//!
//! ## So in the end
//! I just keep increasing the repetitions until it works.
//! Non-parallel probing did not work reliably either and was a whole lot slower.
//! So I turned the parallel iterator back on and just increased the number.
//!
//! At about 13 probes per option, i recovered the mac in 2 out of 3 tries in under 20 seconds each.
//! And the overall ordering of the probes did not matter, so i refactored and result stayed the same:
//!
//! ```diff
//!  (0..u8::MAX).into_par_iter()
//! -   .chain(0..u8::MAX).chain(0..u8::MAX)
//! -   .chain(0..u8::MAX).chain(0..u8::MAX).chain(0..u8::MAX).chain(0..u8::MAX)
//! -   .chain(0..u8::MAX).chain(0..u8::MAX).chain(0..u8::MAX).chain(0..u8::MAX)
//! +   .flat_map(|byte| vec!(byte; 13))
//! ```
//! I declare the challenge solved :D

use std::collections::HashMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

use cyptopals::sha1::MySha1;
use cyptopals::{random_128_bit, u32_be_bytes};

fn bruteforce(mac_len: usize, call: &mut (dyn Fn(&Vec<u8>) -> bool + Sync)) -> Vec<u8> {
    let mut mac = vec![0u8; mac_len];
    for i in 0..mac_len {
        let start = Instant::now();
        let options = time_options(call, &mut mac, i);
        let byte = select_best_option(options).expect("there has to be one option");
        println!("{}: final {} in {:?}", i, byte, start.elapsed());
        mac[i] = byte;
    }
    mac
}

fn time_options(
    call: &mut (dyn Fn(&Vec<u8>) -> bool + Sync),
    mac: &mut Vec<u8>,
    i: usize,
) -> Vec<(u8, u32)> {
    const REPEAT: usize = 13;
    (0..u8::MAX)
        .into_par_iter()
        .flat_map(|byte| vec![byte; REPEAT])
        .map(|possible_byte| {
            let mut par_mac = mac.clone();
            par_mac[i] = possible_byte;
            let start = Instant::now();
            if call(&par_mac) {
                // can't use max, since they are added while selecting the best
                return (possible_byte, u32::MAX >> 4);
            }
            let duration = start.elapsed();
            (possible_byte, duration.as_millis() as u32)
        })
        .collect()
}

/// just take the smallest duration for now
fn select_best_option(options: Vec<(u8, u32)>) -> Option<u8> {
    // let mut m: HashMap<u8, u32> = (u8::MIN..u8::MAX).zip(vec![u32::MAX; 256]).collect();
    let mut m: HashMap<u8, u32> = (u8::MIN..u8::MAX).zip(vec![0u32; 256]).collect();
    for (byte, duration) in options {
        let tmp = m[&byte] + duration;
        m.insert(byte, tmp);
    }
    let mut v: Vec<(u8, u32)> = m.into_iter().collect();
    v.sort_by_key(|x| u32::MAX - x.1);
    println!("Options: {:?}", v);
    println!("Options: {:?}", &v[0..3]);
    Some(v.get(0).expect("at least 1").0)
}

fn insecure_equals(a: &Vec<u8>, b: &Vec<u8>) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        sleep(Duration::from_millis(5));
        if a[i] != b[i] {
            return false;
        }
    }
    return true;
}

fn main() {
    // give rayon 256 threads, one for each option of u8.
    // This is not a problem, since the majority of the time is spent waiting for sleeps to finish
    ThreadPoolBuilder::new()
        .num_threads(256)
        .build_global()
        .expect("should succeed");

    let key = random_128_bit();
    let data = b"malicious file".to_vec();
    let correct_mac = u32_be_bytes(&MySha1::hmac(&key, &data));
    println!("target: {:?}", correct_mac);
    let start = Instant::now();
    let bf_mac = bruteforce(20, &mut |mac: &Vec<u8>| {
        insecure_equals(&u32_be_bytes(&MySha1::hmac(&key, &data)), mac)
    });
    println!("took: {:?}", start.elapsed());
    println!("should be: {:?}", correct_mac);
    println!("was      : {:?}", bf_mac);
    assert_eq!(bf_mac, correct_mac)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_with_very_short_mac() {
        ThreadPoolBuilder::new()
            .num_threads(256)
            .build_global()
            .expect("should succeed");
        let test_mac = vec![5u8; 3];
        let bf_mac = bruteforce(3, &mut |mac: &Vec<u8>| insecure_equals(&test_mac, mac));
        assert_eq!(bf_mac, test_mac)
    }
}
