use tfhe::integer::{RadixCiphertextBig, ServerKey};
use crate::integer_ops::{ch, maj, sigma0, sigma1, sigma_upper_case_0, sigma_upper_case_1};

pub fn sha256_fhe(padded_input: Vec<RadixCiphertextBig>, sk: &ServerKey) -> Vec<RadixCiphertextBig> {
    assert_eq!(padded_input.len() % 16, 0, "padded input length is not a multiple of 16");

    // Initialize hash values
    let mut hash: [RadixCiphertextBig; 8] = [
        sk.create_trivial_radix(u32::from_str_radix("6a09e667", 16).unwrap() as u64, 16),
        sk.create_trivial_radix(u32::from_str_radix("bb67ae85", 16).unwrap() as u64, 16),
        sk.create_trivial_radix(u32::from_str_radix("3c6ef372", 16).unwrap() as u64, 16),
        sk.create_trivial_radix(u32::from_str_radix("a54ff53a", 16).unwrap() as u64, 16),
        sk.create_trivial_radix(u32::from_str_radix("510e527f", 16).unwrap() as u64, 16),
        sk.create_trivial_radix(u32::from_str_radix("9b05688c", 16).unwrap() as u64, 16),
        sk.create_trivial_radix(u32::from_str_radix("1f83d9ab", 16).unwrap() as u64, 16),
        sk.create_trivial_radix(u32::from_str_radix("5be0cd19", 16).unwrap() as u64, 16),
    ];

    let chunks = padded_input.chunks(16);

    for chunk in chunks {

        // Compute the 64 words
        let mut w = initialize_w(&sk);

        for i in 0..16 {
            w[i] = chunk[i].clone();
        }

        for i in 16..64 {
            w[i] = sk.smart_add_parallelized(&mut sk.smart_add_parallelized(&mut sk.smart_add_parallelized(&mut sigma1(&w[i - 2], sk), &mut w[i - 7]), &mut sigma0(&w[i - 15], sk)), &mut w[i - 16]);
        }

        let mut a = hash[0].clone();
        let mut b = hash[1].clone();
        let mut c = hash[2].clone();
        let mut d = hash[3].clone();
        let mut e = hash[4].clone();
        let mut f = hash[5].clone();
        let mut g = hash[6].clone();
        let mut h = hash[7].clone();

        // Compression loop
        for i in 0..64 {
            let k = u32::from_str_radix(K[i], 16).unwrap(); // constant value

            let mut temp1 = sk.smart_add_parallelized(&mut sk.smart_add_parallelized(&mut sk.smart_add_parallelized(&mut sk.smart_add_parallelized(&mut h, &mut ch(&e, &f, &g, sk)), &mut w[i]), &mut sk.create_trivial_radix(k as u64, 16)), &mut sigma_upper_case_1(&e, sk));
            let mut temp2 = sk.smart_add_parallelized(&mut sigma_upper_case_0(&a, sk), &mut maj(&a, &b, &c, sk));
            h = g;
            g = f;
            f = e;
            e = sk.smart_add_parallelized(&mut d, &mut temp1);
            d = c;
            c = b;
            b = a;
            a = sk.smart_add_parallelized(&mut temp1, &mut temp2);
        }

        hash[0] = sk.smart_add_parallelized(&mut hash[0], &mut a);
        hash[1] = sk.smart_add_parallelized(&mut hash[1], &mut b);
        hash[2] = sk.smart_add_parallelized(&mut hash[2], &mut c);
        hash[3] = sk.smart_add_parallelized(&mut hash[3], &mut d);
        hash[4] = sk.smart_add_parallelized(&mut hash[4], &mut e);
        hash[5] = sk.smart_add_parallelized(&mut hash[5], &mut f);
        hash[6] = sk.smart_add_parallelized(&mut hash[6], &mut g);
        hash[7] = sk.smart_add_parallelized(&mut hash[7], &mut h);
    }

    // Concatenate the final hash values to produce a 256-bit hash
    let mut output = vec![];

    for i in 0..8 {
        output.push(hash[i].clone());
    }

    output
}

// Initialize the 64 words with trivial encryptions
fn initialize_w(sk: &ServerKey) -> [RadixCiphertextBig; 64] {
    let t = || -> RadixCiphertextBig { // captures server key for brevity
        sk.create_trivial_zero_radix(16)
    };

    [
        t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),
        t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),
        t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t(),t()
    ]
}

const K: [&str; 64] = [
    "428a2f98", "71374491", "b5c0fbcf", "e9b5dba5", "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
    "d807aa98", "12835b01", "243185be", "550c7dc3", "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
    "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc", "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
    "983e5152", "a831c66d", "b00327c8", "bf597fc7", "c6e00bf3", "d5a79147", "06ca6351", "14292967",
    "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13", "650a7354", "766a0abb", "81c2c92e", "92722c85",
    "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3", "d192e819", "d6990624", "f40e3585", "106aa070",
    "19a4c116", "1e376c08", "2748774c", "34b0bcb5", "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
    "748f82ee", "78a5636f", "84c87814", "8cc70208", "90befffa", "a4506ceb", "bef9a3f7", "c67178f2"
];