use sha256::Sha256;

fn main() {
    let mut ctx: Sha256 = Sha256::init();

    let m: &mut Vec<u8> = &mut String::from("A").into_bytes();
    println!("Update");
    ctx.update(m);
    println!("Digest");
    ctx.digest();
}