use tfhe::integer::{RadixCiphertextBig, ServerKey};

pub fn sigma0(x: &RadixCiphertextBig, sk: &ServerKey) -> RadixCiphertextBig {
    let mut a = rotate_right(x, 7, sk);
    let mut b = rotate_right(x, 18, sk);
    let mut c = sk.scalar_right_shift_parallelized(x, 3);

    let mut result = sk.smart_bitxor_parallelized(&mut a, &mut b);
    sk.smart_bitxor_parallelized(&mut result, &mut c)
}

pub fn sigma1(x: &RadixCiphertextBig, sk: &ServerKey) -> RadixCiphertextBig {
    let mut a = rotate_right(x, 17, sk);
    let mut b = rotate_right(x, 19, sk);
    let mut c = sk.scalar_right_shift_parallelized(x, 10);

    let mut result = sk.smart_bitxor_parallelized(&mut a, &mut b);
    sk.smart_bitxor_parallelized(&mut result, &mut c)
}

pub fn sigma_upper_case_0(x: &RadixCiphertextBig, sk: &ServerKey) -> RadixCiphertextBig {
    let mut a = rotate_right(x, 2, sk);
    let mut b = rotate_right(x, 13, sk);
    let mut c = rotate_right(x, 22, sk);

    let mut result = sk.smart_bitxor_parallelized(&mut a, &mut b);
    sk.smart_bitxor_parallelized(&mut result, &mut c)
}

pub fn sigma_upper_case_1(x: &RadixCiphertextBig, sk: &ServerKey) -> RadixCiphertextBig {
    let mut a = rotate_right(x, 6, sk);
    let mut b = rotate_right(x, 11, sk);
    let mut c = rotate_right(x, 25, sk);

    let mut result = sk.smart_bitxor_parallelized(&mut a, &mut b);
    sk.smart_bitxor_parallelized(&mut result, &mut c)
}

fn rotate_right(x: &RadixCiphertextBig, n: usize, sk: &ServerKey) -> RadixCiphertextBig {
    let mut x = x.clone();
    let mut left = sk.scalar_right_shift_parallelized(&mut x, n);
    let mut right = sk.scalar_left_shift_parallelized(&mut x, 32 - n);
    sk.smart_bitor_parallelized(&mut left, &mut right)
}

pub fn maj(x: &RadixCiphertextBig, y: &RadixCiphertextBig, z: &RadixCiphertextBig, sk: &ServerKey) -> RadixCiphertextBig {
    let mut x = x.clone();
    let mut y = y.clone();
    let mut z = z.clone();

    let mut left = sk.smart_bitxor_parallelized(&mut y, &mut z);
    let mut right = sk.smart_bitand_parallelized(&mut y, &mut z);
    sk.smart_bitand_assign_parallelized(&mut left, &mut x);

    sk.smart_bitxor_parallelized(&mut left, &mut right)
}

pub fn ch(x: &RadixCiphertextBig, y: &RadixCiphertextBig, z: &RadixCiphertextBig, sk: &ServerKey) -> RadixCiphertextBig {
    let mut x = x.clone();
    let mut y = y.clone();
    let mut z = z.clone();

    let mut left = sk.smart_neg_parallelized(&mut x);
    sk.smart_scalar_sub_assign_parallelized(&mut left, 1);
    let mut right = sk.smart_bitand_parallelized(&mut x, &mut y);
    sk.smart_bitand_assign_parallelized(&mut left, &mut z);

    sk.smart_bitxor_parallelized(&mut left, &mut right)
}

#[cfg(test)]
mod tests {
    use tfhe::integer::gen_keys_radix;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;
    use super::*;

    #[test]
    fn test_sigma0() {
        let (ck, sk) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, 16);

        let input = ck.encrypt(1864398703u32 as u64);
        let output = sigma0(&input, &sk);
        let result: u64 = ck.decrypt(&output);
        let expected = 3470890443u32;

        assert_eq!(result as u32, expected);
    } //the other sigmas are implemented in the same way

    #[test]
    fn test_ch() {
        let (ck, sk) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, 16);

        let e = ck.encrypt(1359893119u32 as u64);
        let f = ck.encrypt(2600822924u32 as u64);
        let g = ck.encrypt(528734635u32 as u64);

        let output = ch(&e, &f, &g, &sk);
        let result: u64 = ck.decrypt(&output);
        let expected = 528861580u32;

        assert_eq!(result as u32, expected);
    }

    #[test]
    fn test_maj() {
        let (ck, sk) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, 16);

        let a = ck.encrypt(1779033703u32 as u64);
        let b = ck.encrypt(3144134277u32 as u64);
        let c = ck.encrypt(1013904242u32 as u64);

        let output = maj(&a, &b, &c, &sk);
        let result: u64 = ck.decrypt(&output);
        let expected = 980412007u32;

        assert_eq!(result as u32, expected);
    }
}