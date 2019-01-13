use nettle::cipher::{Aes128, Cipher};
use nettle::mode::{Cbc, Mode};

use super::xml::TKNHeader;

use self::ivs::{IV, SEED_IV};

mod ivs;

const BLOCK_SIZE: usize = Aes128::BLOCK_SIZE;
const KEY_SIZE: usize = Aes128::KEY_SIZE;


enum PasswordOrOriginParam {
    Password(String),
    Origin(String),
}

impl PasswordOrOriginParam {
    fn value(&self) -> &String {
        match self {
            PasswordOrOriginParam::Password(val)
            | PasswordOrOriginParam::Origin(val) => val
        }
    }
}

struct SecretHashParams {
    password_or_origin: PasswordOrOriginParam,
    destination: String,
    name: String,
}

struct SecretCryptoParams {
    hash_params: SecretHashParams,
    secret: String,
}

fn cbc_hash(output: &mut [u8; BLOCK_SIZE], key: &[u8], iv: &[u8], data: &[u8]) {
    for (idx, &v) in iv.iter().enumerate() {
        output[idx] = v;
    }

    for i in (0..data.len()).step_by(BLOCK_SIZE) {
        xor_block(output, &data[i..i + BLOCK_SIZE]);
        let mut tmp = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE { tmp[i] = output[i]; }
        let mut aes = Aes128::with_encrypt_key(key).unwrap();
        aes.encrypt(&mut tmp, output);
        for i in 0..BLOCK_SIZE { output[i] = tmp[i]; }
    }
}

fn xor_block(first: &mut [u8], second: &[u8]) {
    use std::cmp::min;
    for i in 0..min(first.len(), second.len()) {
        first[i] ^= second[i];
    }
}

fn hash(params: &SecretHashParams) -> [u8; BLOCK_SIZE] {
    let mut data = [0u8; 0x50];
    let mut result = [0u8; BLOCK_SIZE];
    let mut iv = [0u8; BLOCK_SIZE];
    let mut key = [0u8; KEY_SIZE];

    for (idx, name_byte) in params.name.bytes().enumerate() {
        key[idx] = name_byte;
    }

    for (idx, pass_byte) in (0..0x20).zip(params.password_or_origin.value().bytes()) {
        data[idx] = pass_byte;
    }

    for (idx, dest_byte) in (0x20..0x40).zip(params.destination.bytes()) {
        data[idx] = dest_byte;
    }

    for iteration in 0..1000 {
        data[0x4f] = iteration as u8;
        data[0x43] = (iteration >> 8) as u8;
        let mut tmp = [0u8; BLOCK_SIZE];
        cbc_hash(&mut tmp, &key, &iv, &data);
        xor_block(&mut result, &tmp);
    }

    result
}

fn decrypt(xor_bytes: &[u8], data: &[u8], key: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];

    let mut aes = Aes128::with_encrypt_key(key).unwrap();
    aes.encrypt(&mut result, &data);

    xor_block(&mut result, xor_bytes);

    result
}


fn decrypt_secret(secret_params: SecretCryptoParams) -> [u8; BLOCK_SIZE] {
    let hash = hash(&secret_params.hash_params);
    println!("got hash");
    let secret_data = secret_params.secret.into_bytes();
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&b"Secret"[..]);
    data.push(0);
    data.push(0);
    let bytes = secret_params.hash_params.name.bytes();
    let len = bytes.len();
    data.extend(bytes);
    for i in len..8 { data.push(0); }

    println!("data len: {}", data.len());

    let result = decrypt(
        &secret_data[..],
        &data,
        &hash);

    return result;
}

fn compute_key(field: &str, serial: &str, key: [u8; KEY_SIZE], iv: IV) -> [u8; KEY_SIZE] {
    let mut data = [0u8; 0x40];

    use std::cmp::min;
    for i in 0..min(0x20, field.len()) {
        data[i] = field.as_bytes()[i];
    }

    for i in 0x20..(0x20 + min(0x20, serial.len())) {
        data[i] = serial.as_bytes()[i];
    }

    let mut computed_key = [0u8; KEY_SIZE];

    cbc_hash(&mut computed_key, &key, iv.bytes(), &data);

    return computed_key;
}

struct SeedCryptoParams {
    encrypted_seed: Vec<u8>,
    serial: String,
    encryption_key: [u8; BLOCK_SIZE],
}

fn decrypt_seed(seed_params: SeedCryptoParams) -> [u8; BLOCK_SIZE] {
    use std::cmp::min;
    let mut data: Vec<u8> = Vec::new();
    let serial_bytes = seed_params.serial.as_bytes();
    let len = min(8, serial_bytes.len());
    data.extend_from_slice(&serial_bytes[0..len]);
    for i in len..8 { data.push(0); }
    data.extend(b"Seed");
    data.extend_from_slice(&[0, 0, 0, 0]);

    let result = decrypt(
        &seed_params.encrypted_seed,
        &data,
        &seed_params.encryption_key);

    return result;
}

pub fn extract_seed(token: &super::xml::TKNBatch) -> [u8; BLOCK_SIZE] {
    let token = token.clone();
    use base64::decode;
    let secret_params = SecretCryptoParams::from(token.header.clone());
    let key = decrypt_secret(secret_params);
    println!("decrypted secret");
    let seed_params = SeedCryptoParams {
        encrypted_seed: decode(&token.token.seed[1..]).unwrap(),
        encryption_key: key,
        serial: token.token.serial_number,
    };

    decrypt_seed(seed_params)
}

impl From<TKNHeader> for SecretHashParams {
    fn from(header: TKNHeader) -> Self {
        SecretHashParams {
            password_or_origin: PasswordOrOriginParam::Origin(header.origin),
            destination: header.dest,
            name: header.name,
        }
    }
}

impl From<TKNHeader> for SecretCryptoParams {
    fn from(header: TKNHeader) -> Self {
        SecretCryptoParams {
            hash_params: SecretHashParams::from(header.clone()),
            secret: header.secret,
        }
    }
}