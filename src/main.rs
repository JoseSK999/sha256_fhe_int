mod padding;
mod integer_ops;
mod sha256;

use tfhe::integer::{gen_keys_radix, RadixCiphertextBig, RadixClientKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
use crate::padding::{pad_sha256_input, u32s_to_hex_string};
use crate::sha256::sha256_fhe;

fn main() {
    let (ck, sk) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, 16);

    // CLIENT PADS DATA AND ENCRYPTS IT

    let padded_input = pad_sha256_input("supernova");
    let encrypted_input = encrypt_u32s(&padded_input, &ck);

    // SERVER COMPUTES OVER THE ENCRYPTED PADDED DATA

    let encrypted_output = sha256_fhe(encrypted_input, &sk);

    // CLIENT DECRYPTS THE OUTPUT

    let output = decrypt_u32s(&encrypted_output, &ck);
    let outhex = u32s_to_hex_string(output);

    println!("{}", outhex);
}

fn encrypt_u32s(u32s: &Vec<u32>, ck: &RadixClientKey) -> Vec<RadixCiphertextBig> {
    let mut ciphertext = vec![];

    for int in u32s {
        ciphertext.push(ck.encrypt(*int as u64));
    }
    ciphertext
}

fn decrypt_u32s(ciphertext: &Vec<RadixCiphertextBig>, ck: &RadixClientKey) -> Vec<u32> {
    let mut u32s = vec![];

    for cipher in ciphertext {
        let int: u64 = ck.decrypt(&cipher);
        u32s.push(int as u32);
    }
    u32s
}