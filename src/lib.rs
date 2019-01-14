#[macro_use]
extern crate serde_derive;

pub use crate::tokens::{RSAToken, TokenDuration};
pub use crate::tokens::generate::generate;
pub use crate::tokens::xml::{read_file, read_string};

mod tokens;

