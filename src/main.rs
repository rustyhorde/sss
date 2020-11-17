mod constants;

use base64::URL_SAFE_NO_PAD;
use constants::{EXP, LOG};
use rand::Rng;

fn main() {
    println!("Hello, world!");
    let secret = "correct horse battery staple".as_bytes();
    let keys = split(&secret, 5, 3);
    for (idx, key) in keys.iter().enumerate() {
        println!("Key {}: {}", idx + 1, key);
    }
}

fn split(secret: &[u8], parts: usize, threshold: usize) -> Vec<String> {
    let mut values: Vec<Vec<u8>> = vec![vec![0; secret.len()]; parts];

    let _: Vec<()> = secret.iter().enumerate().map(|(idx, secret_byte)| {
        let p = generate(threshold, *secret_byte);
        println!("poly: {:?}", p);
        for i in 1..=parts {
            values[i-1][idx] = eval(&p, i as u8);
        }
    }).collect();

    values.iter().map(|x| base64::encode_config(x, URL_SAFE_NO_PAD)).collect()
}

fn generate(d: usize, x: u8) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut rand_bytes: Vec<u8>;

    loop {
        rand_bytes = (0..d).map(|_| rng.gen::<u8>()).collect();
        if degree(&rand_bytes) == (d - 1) { break; }
    }

    rand_bytes[0] = x;
    rand_bytes
}

fn degree(p: &[u8]) -> usize {
    for i in (1..=(p.len() - 1)).rev() {
        if p[i] != 0 {
            return i;
        }
    }
    0
}

fn eval(p: &[u8], x: u8) -> u8 {
    let mut result = 0;

    for i in (0..=(p.len() - 1)).rev() {
        result = add(mul(result, x), p[i])
    }
    result
}

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[usize::from(LOG[usize::from(a)].wrapping_add(LOG[usize::from(b)]))]
    }
}

fn add(a: u8, b: u8) -> u8 {
    a ^ b
}