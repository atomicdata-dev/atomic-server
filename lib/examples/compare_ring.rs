// I was having some problems with getting the signatures from this Rust library to match with the atomic-react JS implementation.
// This file is for debuggin the relationship between the two.

fn main() {
    // Values to validate output from https://paulmillr.com/ecc/
    let hex_private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let hex_public_key = "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6";
    // The site seems to sign a SHA512 hash of the value...
    let _input_message = "val";
    // ... and this is the SHA-512 hash of that string. Or am I doing something wrong here?
    let input_sha = "08055e8edd362ae08565bba339e41f0dfb61ad30527bf5ed5985c72ec565ccfd4fce93f6590a4fb85f7819371229a9681d9b2c1f134ad8d16ee82d73dfb0919d";
    // This is the signature that is outputted on paulmillr.com
    let signature_correct =
      "8fca64f1e6476ae5e4e978b4f50710bb8d5b86329ce4083247bb254eeb2f4ce18086def1923dbb30c2b758e89c8795a39d68179ed66a4f1799709c37bbb2ff05";
    let signature = sign_message(input_sha, hex_private_key, hex_public_key);

    assert_eq!(signature, signature_correct)
}

/// Signs a string using a base64 encoded ed25519 private key. Outputs a base64 encoded ed25519 signature.
fn sign_message(message: &str, private_key: &str, public_key: &str) -> String {
    let private_key_vec: Vec<u8> = decode_hex(private_key).expect("Invalid Hex String");
    let public_key_vec: Vec<u8> = decode_hex(public_key).expect("Invalid Hex String");
    // I'm using PKCS8 in my actual Rust implementation, but I think this might make things more complicated in this example.
    // I can't get it to match signatures with either.
    // let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(&private_key_vec).unwrap();
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_and_public_key(&private_key_vec, &public_key_vec).unwrap();
    let signature = key_pair.sign(&message.as_bytes());
    let signature_bytes = signature.as_ref();
    encode_hex(signature_bytes)
}

use std::{fmt::Write, num::ParseIntError};

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
