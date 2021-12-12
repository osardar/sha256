use sha256::Sha256;

fn main() {
    let mut ctx: Sha256 = Sha256::init();

    let m: &mut Vec<u8> = &mut String::from("A").into_bytes();
    ctx.update(m);
    ctx.digest();
}