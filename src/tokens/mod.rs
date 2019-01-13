use bytes;

pub mod xml;
mod aes;
pub mod crypto;
pub mod generate;

use self::aes::{KEY_SIZE, BLOCK_SIZE};

pub enum TokenDuration {
    ThirtySecond,
    SixtySecond,
}

impl TokenDuration {
    fn mask(&self) -> u32 {
        match self {
            TokenDuration::ThirtySecond => 0b01,
            TokenDuration::SixtySecond => 0b11
        }
    }

    pub fn time_index<Time: chrono::Timelike>(&self, time: Time) -> usize {
        match self {
            TokenDuration::ThirtySecond => {
                let minute_part: usize = ((time.minute() & self.mask()) as usize) << 3;
                let is_second_30 = if time.second() >= 30 { 0b100 } else { 0 };
                minute_part | is_second_30
            }
            TokenDuration::SixtySecond => {
                ((time.minute() & self.mask()) as usize) << 2
            }
        }
    }

    pub fn adjust_for_hash<Time: chrono::Timelike>(&self, time: Time) -> i32 {
        time.minute() as i32 & self.inverted_mask()
    }


    fn inverted_mask(&self) -> i32 {
        match self {
            TokenDuration::ThirtySecond => !0b01,
            TokenDuration::SixtySecond => !0b11
        }
    }
}

pub struct RSAToken {
    serial_number: String,
    pub token_duration: TokenDuration,
    pub digits: usize,
    pub dec_seed: [u8; KEY_SIZE],

    pub pin: Vec<u8>,
}

impl RSAToken {
    pub fn new(sn: String, token_duration: TokenDuration, digits: usize, pin: Vec<u8>, seed: [u8; KEY_SIZE]) -> RSAToken {
        RSAToken {
            serial_number: sn,
            token_duration,
            digits,
            dec_seed: seed,
            pin,
        }
    }

    pub fn serial_number(&self) -> &str {
        &self.serial_number
    }
}