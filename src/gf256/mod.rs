// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `ssss` GF(2^8)

mod constants;

use constants::{EXP, LOG};
use rand::RngCore;

crate fn generate_coeffs(d: u8, x: u8) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let d_usize = usize::from(d);
    let mut rand_bytes = vec![0; d_usize];

    loop {
        rng.fill_bytes(&mut rand_bytes);
        if degree(&rand_bytes) == (d_usize - 1) {
            break;
        }
    }

    rand_bytes[0] = x;
    rand_bytes
}

crate fn eval(p: &[u8], x: u8) -> u8 {
    let mut result = 0;

    for i in (0..=(p.len() - 1)).rev() {
        result = add(mul(result, x), p[i])
    }
    result
}

crate fn interpolate(points: Vec<Vec<u8>>) -> u8 {
    let x = 0;
    let mut y = 0;

    for i in 0..points.len() {
        let a_x = points[i][0];
        let a_y = points[i][1];
        let mut li = 1;

        for j in 0..points.len() {
            let b_x = points[j][0];
            if i != j {
                li = mul(li, div(sub(x, b_x), sub(a_x, b_x)));
            }
        }
        y = add(y, mul(li, a_y));
    }

    y
}

fn degree(p: &[u8]) -> usize {
    for i in (1..=(p.len() - 1)).rev() {
        if p[i] != 0 {
            return i;
        }
    }
    0
}

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        let a = usize::from(a);
        let b = usize::from(b);
        let left = usize::from(LOG[a]);
        let right = usize::from(LOG[b]);
        EXP[left + right]
    }
}

fn div(a: u8, b: u8) -> u8 {
    mul(a, EXP[255_usize - usize::from(LOG[usize::from(b)])])
}

fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn sub(a: u8, b: u8) -> u8 {
    add(a, b)
}

#[cfg(test)]
mod test {
    use super::{add, degree, div, eval, generate_coeffs, interpolate, mul, sub};

    #[test]
    fn add_works() {
        assert_eq!(122, add(100, 30));
    }

    #[test]
    fn sub_works() {
        assert_eq!(122, sub(100, 30));
    }

    #[test]
    fn mul_works() {
        assert_eq!(167, mul(133, 5));
        assert_eq!(254, mul(90, 21));
        assert_eq!(0, mul(0, 21));
        assert_eq!(0x36, mul(0xb6, 0x53));
    }

    #[test]
    fn div_works() {
        assert_eq!(189, div(90, 21));
        assert_eq!(151, div(6, 55));
        assert_eq!(138, div(22, 192));
        assert_eq!(0, div(0, 192));
    }

    #[test]
    fn mul_is_commutative() {
        for i in 0..255 {
            for j in 0..255 {
                assert_eq!(mul(i, j), mul(j, i));
            }
        }
    }

    #[test]
    fn add_is_commutative() {
        for i in 0..255 {
            for j in 0..255 {
                assert_eq!(add(i, j), add(j, i));
            }
        }
    }

    #[test]
    fn sub_is_inverse_of_add() {
        for i in 0..255 {
            for j in 0..255 {
                assert_eq!(sub(add(i, j), j), i);
            }
        }
    }

    #[test]
    fn div_is_inverse_of_mul() {
        for i in 0..255 {
            for j in 1..255 {
                assert_eq!(div(mul(i, j), j), i);
            }
        }
    }

    #[test]
    fn mul_is_inverse_of_div() {
        for i in 0..255 {
            for j in 1..255 {
                assert_eq!(mul(div(i, j), j), i);
            }
        }
    }

    #[test]
    fn degree_works() {
        assert_eq!(degree(&vec![1, 2]), 1);
        assert_eq!(degree(&vec![1, 2, 0]), 1);
        assert_eq!(degree(&vec![1, 2, 3]), 2);
        assert_eq!(degree(&vec![4]), 0);
    }

    #[test]
    fn eval_works() {
        assert_eq!(eval(&vec![1, 0, 2, 3], 2), 17);
    }

    #[test]
    fn generate_works() {
        let p = generate_coeffs(5, 20);
        assert_eq!(p[0], 20);
        // assert_eq!(p.len(), 6);
        assert!(p[p.len() - 1] != 0);
    }

    #[test]
    fn interpolate_works() {
        assert_eq!(interpolate(vec![vec![1, 1], vec![2, 2], vec![3, 3]]), 0);
        assert_eq!(interpolate(vec![vec![1, 80], vec![2, 90], vec![3, 20]]), 30);
        assert_eq!(
            interpolate(vec![vec![1, 43], vec![2, 22], vec![3, 86]]),
            107
        );
    }
}
