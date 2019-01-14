use stoken;

fn main() -> Result<(), ()> {
    let token = stoken::read_file("tests/test.sdtid");
    let token = stoken::generate(stoken::RSAToken::new(token, [1, 2, 3, 4, 5].to_vec()),
                                 stoken::Utc::now());
    println!("token: {}", token);

    Ok(())
}