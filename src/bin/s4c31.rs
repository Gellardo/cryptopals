//! # Brutally bad hash validation - timing leak
//! use an insecure compare, that adds 50ms per character and returns early
//!
//! ## Basic procedure
//! Manipulate the mac one byte/char at a time.
//! For each position try out all possible values.
//! The [insecure_equals] takes longer if more positions are matched, so choose the longest running option.
//! Continue until you have found the whole mac
//!
//! ## Runtime
//! If we try to guess sequentially, the processing time will be dominated by the slowdown:
//!
//! ```
//! n = length of mac (by comparison increment, e.g. byte, char of the hexadecimal representation)
//! s = slowdown per comparison increment
//! b = number of options (per comparison increment)
//! (+s) = the one instance of +1 positions matching
//! b * s * 1 (+s) + b * s * 2 (+s) + b * s * 3 (+s) ... + b * s * n
//! n-1 * s + b*s* (1 + 2 + 3 + ... + n)
//! (n-1) * s + b*s*n*(n+1)/2
//! ```
//!
//! That explains why the challenge also tells us to implement it on a minimal webserver.
//! Webservers ususally implement some kind of parallel processing of requests.
//! So the logic could send all options for the next position at once instead of having to do them sequentially.
//! That should provide a significant speedup:
//!
//! ```
//! s* (+s) + s*2 (+s) + ... + s*n
//! (n-1) * s + s*n*(n+1)/2
//! ```

use std::ops::Sub;
use std::thread::sleep;
use std::time::{Duration, Instant};

use cyptopals::sha1::MySha1;
use cyptopals::u32_be_bytes;

fn bruteforce_rec(data: &Vec<u8>, call: &mut dyn Fn(&Vec<u8>, &Vec<u8>) -> bool) -> Vec<u8> {
    let mut mac = vec![0u8; 5 * 4];
    rec(0, &mut mac, [0, 0], data, call);
    mac
}

fn rec(pos: usize, mac: &mut Vec<u8>, durations: [u128; 2], data: &Vec<u8>, call: &mut dyn Fn(&Vec<u8>, &Vec<u8>) -> bool) -> bool {
    for i in 0..5 {
        let mut byte = 0u8;
        let mut max_duration = Duration::from_secs(0);
        for possible_byte in u8::MIN..=u8::MAX {
            mac[pos] = possible_byte;
            let start = Instant::now();
            if call(data, &mac) {
                return true;
            }
            let duration = start.elapsed();
            if duration > max_duration {
                println!("{}: better {:?}, {}", pos, duration, possible_byte);
                byte = possible_byte;

                // quick continue if we found it
                // let diff = duration.sub(max_duration).as_millis();
                // if diff > 10 && diff < 25 && max_duration.as_millis() > 0{
                //     break
                // }
                max_duration = duration;
            }
        }
        println!("{}: final {}", pos, byte);
        mac[pos] = byte;
        // slowdown over 2 positions should definitely shrink
        if max_duration.as_millis() - durations[0] < 30 {
            return false;
        }
        let mut new_durations = [0; 2];
        new_durations[0] = durations[1];
        new_durations[1] = max_duration.as_millis();
        if rec(pos + 1, mac, new_durations, data, call) { return true; }
    }
    return false;
}

fn bruteforce(data: &Vec<u8>, call: &mut dyn Fn(&Vec<u8>, &Vec<u8>) -> bool) -> Vec<u8> {
    let mut mac = vec![0u8; 5 * 4];
    for i in 0..mac.len() {
        let mut max_duration = Duration::from_secs(0);
        let mut byte = 0u8;
        for possible_byte in u8::MIN..=u8::MAX {
            mac[i] = possible_byte;
            let start = Instant::now();
            if call(data, &mac) {
                return mac;
            }
            let duration = start.elapsed();
            if duration > max_duration {
                println!("{}: better {:?}, {}", i, duration, possible_byte);
                byte = possible_byte;

                // quick continue if we found it
                // let diff = duration.sub(max_duration).as_millis();
                // if diff > 10 && diff < 25 && max_duration.as_millis() > 0{
                //     break
                // }
                max_duration = duration;
            }
        }
        println!("{}: final {}", i, byte);
        mac[i] = byte;
    }
    mac
}

fn insecure_equals(a: &Vec<u8>, b: &Vec<u8>) -> bool {
    if a.len() != b.len() { return false; }
    for i in 0..a.len() {
        sleep(Duration::from_millis(25));
        if a[i] != b[i] {
            return false;
        }
    }
    return true;
}

fn main() {
    let key = b"abc".to_vec();
    let data = b"malicious file".to_vec();
    let start = Instant::now();
    let bf_mac = bruteforce_rec(
        &data,
        &mut |data, mac: &Vec<u8>| insecure_equals(&u32_be_bytes(&MySha1::hmac(&key, data)), mac));
    println!("took: {:?}", start.elapsed());
    println!("should be: {:?}", u32_be_bytes(&MySha1::hmac(&key, &data)));
    println!("was      : {:?}", bf_mac);
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn placeholder() {
        assert!(true)
    }
}
