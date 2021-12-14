use sha256::Sha256;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("sha256 <input_str>");
        return;
    }

    let mut ctx: Sha256 = Sha256::init();
    let m: &mut Vec<u8> = &mut args[1].clone().into_bytes();
    ctx.update(m);
    println!("{}", ctx.hexdigest().unwrap());
}
