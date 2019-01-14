use base64;
use serde_json::{from_slice, to_vec};

pub fn export(token: super::RSAToken) -> Option<String> {
    let bytes = to_vec(&token).ok()?;
    return Some(base64::encode(&bytes));
}

pub fn import(token: String) -> Option<super::RSAToken> {
    let bytes = base64::decode(&token).ok()?;
    return from_slice(&bytes).ok();
}