use super::aes::KEY_SIZE;

pub struct IV([u8; KEY_SIZE]);

//const BATCH_MAC_IV: IV = IV([
//    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
//]);
//
//const BATCH_ENC_IV: IV = IV([
//    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
//]);
//
//const TOKEN_MAC_IV: IV = IV([
//    0x1b, 0xb6, 0x7a, 0xe8, 0x58, 0x4c, 0xaa, 0x73,
//    0xb2, 0x57, 0x42, 0xd7, 0x07, 0x8b, 0x83, 0xb8
//]);

pub const SEED_IV: IV = IV([
    0x16, 0xa0, 0x9e, 0x66, 0x7f, 0x3b, 0xcc, 0x90, 0x8b, 0x2f, 0xb1, 0x36, 0x6e, 0xa9, 0x57, 0xd3,
]);

impl IV {
    pub fn bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}
