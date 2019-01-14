use super::aes;
use super::aes::{BLOCK_SIZE, KEY_SIZE};
use super::xml::TKNHeader;

use self::ivs::{IV, SEED_IV};

mod ivs;

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
    secret: Vec<u8>,
}

fn cbc_hash(key: &[u8], iv: &[u8], data: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut output = [0u8; BLOCK_SIZE];
    for (idx, &v) in iv.iter().enumerate() {
        output[idx] = v;
    }

    for i in (0..data.len()).step_by(BLOCK_SIZE) {
        xor_block(&mut output, &data[i..i + BLOCK_SIZE]);
        let result = aes::encrypt(key, &output);
        for i in 0..BLOCK_SIZE { output[i] = result[i]; }
    }

    return output;
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
    let iv = [0u8; BLOCK_SIZE];
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
        data[0x4F] = iteration as u8;
        data[0x4E] = (iteration >> 8) as u8;
        let tmp = cbc_hash(&key, &iv, &data);
        xor_block(&mut result, &tmp);
    }

    result
}

fn decrypt(xor_bytes: &[u8], data: &[u8], key: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut result = aes::encrypt(key, data);
    xor_block(&mut result, xor_bytes);
    result
}

fn decrypt_secret(secret_params: SecretCryptoParams) -> [u8; BLOCK_SIZE] {
    let hash = hash(&secret_params.hash_params);
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&b"Secret"[..]);
    data.push(0);
    data.push(0);
    let bytes = secret_params.hash_params.name.bytes();
    let len = bytes.len();
    data.extend(bytes);
    for _ in len..8 { data.push(0); }


    let mut result = aes::encrypt(&hash, &data);
    let secret_data = secret_params.secret.as_ref();
    xor_block(&mut result, &secret_data);
    let result = decrypt(
        &secret_data,
        &data,
        &hash);

    return result;
}

fn compute_key(field: &[u8], serial: &str, key: &[u8], iv: IV) -> [u8; KEY_SIZE] {
    let mut data = [0u8; 0x40];

    use std::cmp::min;
    for i in 0..min(0x20, field.len()) {
        data[i] = field[i];
    }

    let serial_bytes = serial.as_bytes();
    for i in 0x20..(0x20 + min(0x20, serial.len())) {
        data[i] = serial_bytes[i - 0x20];
    }

    return cbc_hash(&key, iv.bytes(), &data);
    /*
	memset(buf, 0, sizeof(buf));
	strncpy(&buf[0x00], str0, 0x20);
	strncpy(&buf[0x20], str1, 0x20);
	cbc_hash(result, key, iv, buf, sizeof(buf));
	static void cbc_hash(uint8_t *result, const uint8_t *key, const uint8_t *iv,
	const uint8_t *data, int len)
	*/
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
    for _ in len..8 { data.push(0); }
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
    let encryption_key = compute_key(b"TokenEncrypt", &token.token.serial_number, &key, SEED_IV);
    let seed_params = SeedCryptoParams {
        encrypted_seed: decode(&token.token.seed[1..]).unwrap(),
        serial: token.token.serial_number,
        encryption_key,
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
            secret: base64::decode(&header.secret).unwrap(),
        }
    }
}