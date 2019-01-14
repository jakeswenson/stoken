use crypto::{blockmodes::NoPadding, aes, aes::KeySize};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

pub const KEY_SIZE: usize = 16;
pub const BLOCK_SIZE: usize = 16;

pub fn encrypt(key: &[u8], data: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut output_array = [0u8; BLOCK_SIZE];
    let mut input = RefReadBuffer::new(&data);
    let mut output: RefWriteBuffer = RefWriteBuffer::new(&mut output_array);

    let mut encryptor = aes::ecb_encryptor(KeySize::KeySize128, key, NoPadding);
    encryptor.encrypt(&mut input, &mut output, true).unwrap();

    return output_array;
}