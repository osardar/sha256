use std::error::Error;

#[macro_export]
macro_rules! overflowing_add {
    ( $( $x:expr ),* ) => {
        {
            let mut tmp: u32 = 0;
            $(
                tmp = tmp.overflowing_add($x).0;
            )*
            tmp
        }
    };
}

#[derive(Debug)]
pub struct Sha256 {
    arr_h: [u32; 8],
    arr_k: [u32; 64],
    cache: Vec<u8>,
    counter: usize,
}

impl Sha256 {
    pub fn init() -> Self {
        let arr_h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let arr_k: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        Sha256 {
            arr_h,
            arr_k,
            cache: Vec::<u8>::new(),
            counter: 0,
        }
    }

    pub fn update(self: &mut Sha256, m: &mut Vec<u8>) -> Result<&[u32; 8], Box<dyn Error>> {
        self.counter += m.len();
        self.cache.append(m);

        let cache = self.cache.clone();
        for chunk in cache.chunks_exact(64) {
            self.compress(&chunk.to_vec());
            self.cache = self.cache[64..].to_vec();
        }

        Ok(&[0; 8])
    }

    fn compress(self: &mut Sha256, c: &Vec<u8>) {
        let mut w: [u32; 64] = [0; 64];
        let c = c.clone();

        for i in 0..16 {
            w[i] = (c[4 * i] as u32) << 24
                | (c[4 * i + 1] as u32) << 16
                | (c[4 * i + 2] as u32) << 8
                | (c[4 * i + 3] as u32);
        }

        let mut w: Vec<u32> = w.to_vec();

        for i in 16..64 {
            w.push(0);

            let s0: u32 =
                (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
            let s1: u32 =
                (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);

            w[i] = overflowing_add!(w[i - 16], s0, w[i - 7], s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h]: [u32; 8] = self.arr_h;

        //let mut s0: u32 = 0;
        let mut s0: u32;
        let mut s1: u32;
        let mut ch: u32;
        let mut temp1: u32;
        let mut temp2: u32;
        let mut maj: u32;

        for i in 0..64 {
            s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = overflowing_add!(s0, maj);
            s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            ch = (e & f) ^ ((!e) & g);
            temp1 = overflowing_add!(h, s1, ch, self.arr_k[i], w[i]);

            h = g;
            g = f;
            f = e;
            e = overflowing_add!(d, temp1);
            d = c;
            c = b;
            b = a;
            a = overflowing_add!(temp1, temp2);
        }

        self.arr_h[0] = overflowing_add!(self.arr_h[0], a);
        self.arr_h[1] = overflowing_add!(self.arr_h[1], b);
        self.arr_h[2] = overflowing_add!(self.arr_h[2], c);
        self.arr_h[3] = overflowing_add!(self.arr_h[3], d);
        self.arr_h[4] = overflowing_add!(self.arr_h[4], e);
        self.arr_h[5] = overflowing_add!(self.arr_h[5], f);
        self.arr_h[6] = overflowing_add!(self.arr_h[6], g);
        self.arr_h[7] = overflowing_add!(self.arr_h[7], h);
    }

    fn pad(self: &Sha256, msglen: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        let mdi = msglen & 0x3F;
        let mut length: Vec<u8> = ((msglen as u64) << 3).to_be_bytes().to_vec();
        let padlen;

        if mdi < 56 {
            padlen = 55 - mdi
        } else {
            padlen = 119 - mdi
        }

        let mut pad: Vec<u8> = Vec::<u8>::new();
        pad.push(0x80);
        for _i in 0..padlen {
            pad.push(0);
        }
        pad.append(&mut length);

        Ok(pad)
    }

    pub fn digest(self: &mut Sha256) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut pad = self.pad(self.counter).unwrap();
        self.update(&mut pad);

        let mut tmp: Vec<u8> = Vec::<u8>::new();
        for h in self.arr_h.clone() {
            for h_byte in h.to_be_bytes() {
                tmp.push(h_byte);
            }
        }

        Ok(tmp.clone())
    }

    pub fn hexdigest(self: &mut Sha256) -> Result<String, Box<dyn Error>> {
        let digest: Vec<u8> = self.digest().unwrap();
        let mut hexdigest = String::new();
        for byte in digest {
            hexdigest += &format!("{:02x}", byte);
        }
        Ok(hexdigest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let mut ctx: Sha256 = Sha256::init();
        let mut m: Vec<u8> = Vec::<u8>::new();
        ctx.update(&mut m);
        assert_eq!(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ctx.hexdigest().unwrap()
        );
    }

    #[test]
    fn test_1b() {
        let mut ctx: Sha256 = Sha256::init();
        let mut m: Vec<u8> = "A".as_bytes().to_vec();
        ctx.update(&mut m);
        assert_eq!(
            "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
            ctx.hexdigest().unwrap()
        );
    }

    #[test]
    fn test_4b() {
        let mut ctx: Sha256 = Sha256::init();
        let mut m: Vec<u8> = "A".repeat(4).as_bytes().to_vec();
        ctx.update(&mut m);
        assert_eq!(
            "63c1dd951ffedf6f7fd968ad4efa39b8ed584f162f46e715114ee184f8de9201",
            ctx.hexdigest().unwrap()
        );
    }

    #[test]
    fn test_64b() {
        let mut ctx: Sha256 = Sha256::init();
        let mut m: Vec<u8> = "A".repeat(64).as_bytes().to_vec();
        ctx.update(&mut m);
        assert_eq!(
            "d53eda7a637c99cc7fb566d96e9fa109bf15c478410a3f5eb4d4c4e26cd081f6",
            ctx.hexdigest().unwrap()
        );
    }

    #[test]
    fn test_128b() {
        let mut ctx: Sha256 = Sha256::init();
        let mut m: Vec<u8> = "A".repeat(128).as_bytes().to_vec();
        ctx.update(&mut m);
        assert_eq!(
            "b6ac3cc10386331c765f04f041c147d0f278f2aed8eaa021e2d0057fc6f6ff9e",
            ctx.hexdigest().unwrap()
        );
    }
}
