use chrono::{Datelike, Timelike};

use crate::tokens::RSAToken;

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
            assert_eq!(bcd2(31), 48);
        }
    }
}

fn generate<DateTime: Timelike + Datelike + Copy>(token: RSAToken, time: DateTime) -> String {
    use self::bcd::{bcd2, bcd4};
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

    println!("bcd: {:?}", bcd_time);

//    key_from_time(bcd_time, 2, t->serial, key0);
//    stc_aes128_ecb_encrypt(t->dec_seed, key0, key0);
    let first_key = key_from_time(&bcd_time[0..2], token.serial_number());
    let mut first_pass = encrypt(&token.dec_seed, &first_key);

    //    key_from_time(bcd_time, 3, t->serial, key1);
//    stc_aes128_ecb_encrypt(key0, key1, key1);
    let second_key = key_from_time(&bcd_time[0..3], token.serial_number());
    let mut second_pass = encrypt(&first_pass, &second_key);

//    key_from_time(bcd_time, 4, t->serial, key0);
//    stc_aes128_ecb_encrypt(key1, key0, key0);
    let third_key = key_from_time(&bcd_time[0..4], token.serial_number());
    let mut third_pass = encrypt(&second_pass, &third_key);

//    key_from_time(bcd_time, 5, t->serial, key1);
//    stc_aes128_ecb_encrypt(key0, key1, key1);
    let fourth_key = key_from_time(&bcd_time[0..5], token.serial_number());
    let mut fourth_pass = encrypt(&third_pass, &fourth_key);

//    key_from_time(bcd_time, 8, t->serial, key0);
//    stc_aes128_ecb_encrypt(key1, key0, key0);
    let fifth_key = key_from_time(&bcd_time[0..8], token.serial_number());
    let mut fifth_pass = encrypt(&fourth_pass, &fifth_key);

//    /* key0 now contains 4 consecutive token codes */
//    if (is_30)
//    i = ((gmt.tm_min & 0x01) << 3) | ((gmt.tm_sec >= 30) << 2);
//    else
//    i = (gmt.tm_min & 0x03) << 2;
    let index = token.token_duration.time_index(time);

    println!("Time Index: {}", index);

//
//    tokencode = (key0[i + 0] << 24) | (key0[i + 1] << 16) |
//        (key0[i + 2] << 8)  | (key0[i + 3] << 0);
    let mut token_code =
        first_pass[(index + 0)..(index + 4)].iter()
            .fold(0, |acc, &byte| (acc << 2) | byte as u32);


    let mut code_out = String::new();

    for i in 0..token.digits {
        let mut dig = token_code % 10;
        token_code /= 10;

        if i < token.pin.len() {
            let pin_dig = token.pin[token.pin.len() - i - 1];
            dig += pin_dig as u32;
        }

        code_out.push(((dig % 10) as u8 + b'0') as char)
    }

    code_out
//
//    /* populate code_out backwards, adding PIN digits if available */
//    j = ((t->flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) + 1;
//    code_out[j--] = 0;
//    for (i = 0; j >= 0; j--, i++) {
//        uint8_t c = tokencode % 10;
//        tokencode /= 10;
//
//        if (i < pin_len)
//        c += t->pin[pin_len - i - 1] - '0';
//        code_out[j] = c % 10 + '0';
}

fn encrypt(key: &[u8], data: &[u8]) -> [u8; 16] {
    use nettle::cipher::{Cipher, Aes128};
    let mut output = [0u8; 16];

    let mut s: Aes128 = Aes128::with_encrypt_key(key).unwrap();
    s.encrypt(&mut output, data);

    output
}

fn key_from_time(bcd_time: &[u8], serial: &str) -> [u8; 16] {
    use std::iter::Iterator;
    let mut buf = [0u8; 16];
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use chrono::{Datelike, DateTime, FixedOffset, Timelike, TimeZone, Utc};

    use crate::tokens::{RSAToken, TokenDuration};

    #[test]
    fn generate() {
        use crate::tokens::{xml, xml::TKNBatch};
        use crate::tokens::crypto;
        use std::env;

        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/test.sdtid");

        println!("Test: {:?}", d);

        let token = xml::read_file(d);
        let decrypted_seed = crypto::extract_seed(&token);

        let token = RSAToken::new(
            token.token.serial_number,
            TokenDuration::SixtySecond,
            token.header.digits,
            [1, 2, 3, 4, 5].to_vec(),
            decrypted_seed);

        let time = FixedOffset::east(0).ymd(2019, 1, 13).and_hms(2, 08, 42);

        let output = super::generate(token, time);
        println!("Token: {}", output);
    }
}

