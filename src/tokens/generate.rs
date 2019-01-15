use chrono::{Datelike, Timelike};

use crate::tokens::RSAToken;

use super::aes::KEY_SIZE;

mod bcd {
    const fn tens(num: i32) -> u8 {
        ((num / 10) % 10) as u8
    }

    const fn ones(num: i32) -> u8 {
        (num % 10) as u8
    }

    pub const fn bcd2(num: i32) -> u8 {
        tens(num) << 4 | ones(num)
    }

    pub const fn bcd4(num: i32) -> (u8, u8) {
        (bcd2(num / 100), bcd2(num % 100))
    }

    #[cfg(test)]
    mod tests {
        use super::{bcd2, bcd4};

        #[test]
        fn wiki() {

            // https://en.wikipedia.org/wiki/Binary-coded_decimal#Basics
            assert_eq!(bcd2(91), 0b1001_0001);
            assert_eq!(bcd2(01), 0b0000_0001);
            assert_eq!(bcd2(23), 0b0010_0011);
            assert_eq!(bcd2(45), 0b0100_0101);
            assert_eq!(bcd2(67), 0b0110_0111);
            assert_eq!(bcd2(89), 0b1000_1001);

            let bcd9876 = bcd4(9876);
            assert_eq!(
                bcd9876,
                (0b1001_1000, 0b0111_0110),
                "9876 should was {:#b}, {:#b}",
                bcd9876.0,
                bcd9876.1);

            let bcd2019 = bcd4(2019);
            assert_eq!(
                bcd2019,
                (0b0010_0000, 0b0001_1001),
                "2019 should was {:#b}, {:#b}",
                bcd2019.0,
                bcd2019.1);

            assert_eq!(bcd4(2019), (32, 25));
            assert_eq!(bcd2(1), 1);
            assert_eq!(bcd2(13), 19);
            assert_eq!(bcd2(5), 5);
            assert_eq!(bcd2(31), 49);
        }
    }
}

fn key_from_time(bcd_time: &[u8], serial: &str) -> [u8; KEY_SIZE] {
    use std::iter::Iterator;
    let mut buf = [0u8; KEY_SIZE];
    for i in 0..8 { buf[i] = 0xAA }
    for i in 0..bcd_time.len() { buf[i] = bcd_time[i] }
    for i in 12..buf.len() { buf[i] = 0xBB }

    let serial_bytes: Vec<u8> = serial.as_bytes().iter().map(|v| v - b'0').collect();

    let mut buf_pos = 8;
    for i in (4..12).step_by(2) {
        buf[buf_pos] = serial_bytes[i] << 4 | serial_bytes[i + 1];
        buf_pos += 1;
    }

    return buf;
}

pub fn generate<DateTime: Timelike + Datelike + Copy>(token: RSAToken, time: DateTime) -> String {
    use self::bcd::{bcd2, bcd4};
    use super::aes::encrypt;
    let (year_first, year_second) = bcd4(time.year());
    let month = bcd2(time.month() as i32);
    let day = bcd2(time.day() as i32);
    let hour = bcd2(time.hour() as i32);
    let minute = bcd2(token.token_duration.adjust_for_hash(time));

    let bcd_time: [u8; 8] = [
        year_first,
        year_second,
        month,
        day,
        hour,
        minute,
        0,
        0
    ];

    let first_key = key_from_time(&bcd_time[..2], token.serial_number());
    let first_pass = encrypt(token.dec_seed.as_ref(), &first_key);

    let second_key = key_from_time(&bcd_time[..3], token.serial_number());
    let second_pass = encrypt(&first_pass, &second_key);

    let third_key = key_from_time(&bcd_time[..4], token.serial_number());
    let third_pass = encrypt(&second_pass, &third_key);

    let fourth_key = key_from_time(&bcd_time[..5], token.serial_number());
    let fourth_pass = encrypt(&third_pass, &fourth_key);

    let fifth_key = key_from_time(&bcd_time[..8], token.serial_number());
    let fifth_pass = encrypt(&fourth_pass, &fifth_key);

    let index = token.token_duration.time_index(time);

    let mut token_code =
        fifth_pass[(index + 0)..(index + 4)].iter()
            .fold(0, |acc, &byte| (acc << 8) | byte as u32);

    let mut code_out = String::new();

    let pin: Vec<u8> = token.pin.as_bytes().iter().map(|b| b - b'0').collect();

    for i in 0..token.digits {
        let mut dig = token_code % 10;
        token_code /= 10;

        if i < pin.len() {
            let pin_dig = pin[pin.len() - i - 1];
            dig += pin_dig as u32;
        }

        code_out.insert(0, ((dig % 10) as u8 + b'0') as char);
    }

    code_out
}

#[cfg(test)]
pub mod tests {
    use std::path::PathBuf;

    use chrono::{FixedOffset, TimeZone, Utc};

    use crate::tokens::RSAToken;

    pub fn test_file() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/test.sdtid");
        path
    }

    #[test]
    fn generate() {
        use crate::tokens::xml;
        use crate::tokens::crypto;

        println!("Test: {:?}", test_file());

        let token = xml::read_file(test_file());
        let decrypted_seed = crypto::extract_seed(&token);
        println!("seed: {:X?}", decrypted_seed);

        let token = RSAToken::from_xml(token, "12345");

        let time = FixedOffset::east(0).ymd(2019, 1, 13).and_hms(21, 19, 34);

        let output = super::generate(token, time);
        println!("Token: {}", output);
        assert_eq!(output, "93659800");
    }

    #[test]
    fn generate_now() {
        use super::super::xml;

        println!("Test: {:?}", test_file());

        let token = xml::read_file(test_file());

        let token = RSAToken::from_xml(token, "12345");

        let output = super::generate(token, Utc::now());
        println!("Token: {}", output);
    }
}

