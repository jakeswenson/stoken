pub mod xml;
mod aes;
pub mod crypto;
pub mod generate;

pub enum TokenDuration {
    ThirtySecond,
    SixtySecond,
}

impl TokenDuration {
    pub fn time_index<Time: chrono::Timelike>(&self, time: Time) -> usize {
        match self {
            TokenDuration::ThirtySecond => {
                let minute_part: usize = ((time.minute() & 0b01) as usize) << 3;
                let second_half = if time.second() >= 30 { 0b100 } else { 0b000 };
                minute_part | second_half
            }
            TokenDuration::SixtySecond => {
                ((time.minute() & 0b11) as usize) << 2
            }
        }
    }

    pub fn adjust_for_hash<Time: chrono::Timelike>(&self, time: Time) -> i32 {
        time.minute() as i32 & match self {
            TokenDuration::ThirtySecond => !0b01,
            TokenDuration::SixtySecond => !0b11
        }
    }
}

use self::aes::KEY_SIZE;
pub struct RSAToken {
    serial_number: String,
    pub token_duration: TokenDuration,
    pub digits: usize,
    pub dec_seed: [u8; KEY_SIZE],
    pub pin: Vec<u8>,
}

impl RSAToken {
    pub fn new(token: self::xml::TKNBatch, pin: Vec<u8>) -> RSAToken {
        let seed = self::crypto::extract_seed(&token);
        RSAToken {
            serial_number: token.token.serial_number,
            token_duration: TokenDuration::SixtySecond,
            digits: token.header.number_of_digits,
            dec_seed: seed,
            pin,
        }
    }

    pub fn serial_number(&self) -> &str {
        &self.serial_number
    }
}