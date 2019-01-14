use std::fs::File;
use std::path::Path;

use serde_xml_rs::{from_reader, from_str};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TKNHeader {
    pub version: i32,
    pub secret: String,
    pub origin: String,
    pub dest: String,
    pub name: String,

    #[serde(rename = "HeaderMAC")]
    pub mac: String,
    #[serde(rename = "DefInterval")]
    pub interval: i32,

    #[serde(rename = "DefBirth")]
    pub start: String,

    #[serde(rename = "DefDeath")]
    pub end: String,

    #[serde(rename = "DefAlg")]
    pub alg: i32,

    #[serde(rename = "DefDigits")]
    pub number_of_digits: usize,

    #[serde(rename = "DefMode")]
    pub mode: i32,

    #[serde(rename = "DefAddPIN")]
    pub add_pin: i32,

    #[serde(rename = "DefLocalPIN")]
    pub local_pin: i32,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TKN {
    #[serde(rename = "SN")]
    pub serial_number: String,
    pub seed: String,
    pub user_first_name: String,
    pub user_last_name: String,
    pub user_login: String,
    pub pin_type: Option<i32>,
    #[serde(rename = "TokenMAC")]
    pub mac: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct TKNTrailer {
    #[serde(rename = "BatchSignature")]
    pub signature: String,
    #[serde(rename = "BatchCertificate")]
    pub certificate: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct TKNBatch {
    #[serde(rename = "TKNHeader")]
    pub header: TKNHeader,
    #[serde(rename = "TKN")]
    pub token: TKN,
    #[serde(rename = "TKNTrailer")]
    pub trailer: TKNTrailer,
}

pub fn read_file<P: AsRef<Path>>(file_path: P) -> TKNBatch {
    let file = File::open(file_path).unwrap();
    from_reader(file).unwrap()
}

pub fn read_string(contents: &str) -> TKNBatch {
    from_str(contents).unwrap()
}


#[cfg(test)]
mod tests {
    #[test]
    fn parse_xml_succeeds() {
        use crate::tokens::generate::tests::test_file;
        let token = super::read_file(test_file());
        println!("{:?}", token);
        assert_eq!(token.token.user_login, "jake");
    }
}