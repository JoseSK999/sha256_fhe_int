# sha256_fhe_int
This repo contains a integer based version of our boolean [homomorphic sha256 implementation](https://github.com/JoseSK999/sha256_fhe). We use the ```RadixCiphertextBig``` type to represent u32 values and operate modulo 2^32 with them.

The main difference is that here we evaluate the ```rotate_right``` and ```right_shift``` functions homomorphically since we can no longer rearrange the bool ciphertexts. Right shift is provided as a method on ```ServerKey``` while the homomorphic rotate right operation is implemented as follows.

```rust
fn rotate_right(x: &RadixCiphertextBig, n: usize, sk: &ServerKey) -> RadixCiphertextBig {
    let mut x = x.clone();
    let mut left = sk.scalar_right_shift_parallelized(&mut x, n);
    let mut right = sk.scalar_left_shift_parallelized(&mut x, 32 - n);
    sk.smart_bitor_parallelized(&mut left, &mut right)
}
```



