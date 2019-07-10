use stoken;

fn main() -> Result<(), ()> {
    let token = stoken::read_file("tests/test.sdtid");
    let token = stoken::generate(
        stoken::RSAToken::from_xml(token, "12345"),
        stoken::Utc::now(),
    );
    println!("token: {}", token);

    Ok(())
}
