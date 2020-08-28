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
//!
//! So I looked at how to do the compares/"calls to the webserver" in parallel myself and... saw no simple way to do so.
//! Instead, I used the `rayon` library to allow for really easy parallelism.
//! The only change required is to go from a `for`-loop to `iter()` based code and replace `iter` with `par_iter`.
//! Done... well almost, now increase the thread pool size to 256, since none of the threads will do significant work.
//! More makes no sense since there are only 256 possible values to explore.
//! And lo and behold, the results were as expected:
//!
//! | version | runtime |
//! |---------|---------|
//! | v1 (no rayon) | > 40 min |
//! | rayon defaults | ~ 6 min |
//! | rayon 256 | ~ 13 sec |

use std::thread::sleep;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

use cyptopals::{random_128_bit, u32_be_bytes};
use cyptopals::sha1::MySha1;

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

fn time_options(call: &mut (dyn Fn(&Vec<u8>) -> bool + Sync), mac: &mut Vec<u8>, i: usize) -> Vec<(u8, u32)> {
    (0..u8::MAX).into_par_iter().map(|possible_byte| {
        let mut par_mac = mac.clone();
        par_mac[i] = possible_byte;
        let start = Instant::now();
        if call(&par_mac) {
            return (possible_byte, u32::MAX);
        }
        let duration = start.elapsed();
        (possible_byte, duration.as_millis() as u32)
    }).collect()
}

/// just take the smallest duration for now
fn select_best_option(options: Vec<(u8, u32)>) -> Option<u8> {
    options.iter().max_by(|f, s| f.1.cmp(&s.1)).map(|o| o.0)
}

fn insecure_equals(a: &Vec<u8>, b: &Vec<u8>) -> bool {
    if a.len() != b.len() { return false; }
    for i in 0..a.len() {
        sleep(Duration::from_millis(50));
        if a[i] != b[i] {
            return false;
        }
    }
    return true;
}

fn main() {
    // give rayon 256 threads, one for each option of u8.
    // This is not a problem, since the majority of the time is spent waiting for sleeps to finish
    ThreadPoolBuilder::new().num_threads(256).build_global().expect("should succeed");

    let key = random_128_bit();
    let data = b"malicious file".to_vec();
    let correct_mac = u32_be_bytes(&MySha1::hmac(&key, &data));
    println!("target: {:?}", correct_mac);
    let start = Instant::now();
    let bf_mac = bruteforce(20, &mut |mac: &Vec<u8>| insecure_equals(&u32_be_bytes(&MySha1::hmac(&key, &data)), mac));
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
        ThreadPoolBuilder::new().num_threads(256).build_global().expect("should succeed");
        let test_mac = vec!(5u8; 3);
        let bf_mac = bruteforce(3, &mut |mac: &Vec<u8>| insecure_equals(&test_mac, mac));
        assert_eq!(bf_mac, test_mac)
    }
}
