use std::error::Error;

fn compression(chunks: &mut Vec<Vec<u32>>) {
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

    let mut a: u32 = arr_h[0];
    let mut b: u32 = arr_h[1];
    let mut c: u32 = arr_h[2];
    let mut d: u32 = arr_h[3];
    let mut e: u32 = arr_h[4];
    let mut f: u32 = arr_h[5];
    let mut g: u32 = arr_h[6];
    let mut h: u32 = arr_h[7];

    let mut s0: u32 = 0;
    let mut s1: u32 = 0;
    let mut ch: u32 = 0;
    let mut temp1: u32 = 0;
    let mut temp2: u32 = 0;
    let mut maj: u32 = 0;

    /*
        S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        ch := (e and f) xor ((not e) and g)
        temp1 := h + S1 + ch + k[i] + w[i]
        S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        maj := (a and b) xor (a and c) xor (b and c)
        temp2 := S0 + maj
 
        h := g
        g := f
        f := e
        e := d + temp1
        d := c
        c := b
        b := a
        a := temp1 + temp2
    */

    let mut i = 0; // trait issue when attempting to use enumerate
    for chunk in chunks {   
        println!("iter: {}", i);
        s1 = (e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25));
        ch = ((e & f) ^ ((!e) & g));
        temp1 = (h + s1 + ch + arr_k[i] + chunk[i]);     
        s0 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)) ;
        maj = ((a & b) ^ (a & c) ^ (b & c));
        println!("s0: {:#x} maj: {:#x}", s0, maj);
        temp2 = (s0 + maj) % u32::pow(2,32);

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;

        i += 1;
    }
}

fn get_chunks_512(in_bytes: &mut Vec<u8>) -> Result<Vec<Vec<u32>>, Box<dyn Error>> {
    let extended_chunks: Vec<Vec<u32>> = in_bytes.chunks(512 / 8).map(|x| {
        let chunk_bytes = x.clone();

        //convert from Vec<u8> to Vec<u32>
        let mut chunk_words: Vec<u32> = chunk_bytes
            .chunks(4)
            .map(|y| {
                let chunk = y.clone();
                let mut word: u32 = 0;
                word = ((chunk[0] as u32) << 24
                    | (chunk[1] as u32) << 16
                    | (chunk[2] as u32) << 8
                    | (chunk[0] as u32))
                    .into();
                word
            })
            .collect::<Vec<u32>>();

        for i in 16..63 {
            chunk_words.push(0);

            let s0: u32 = (chunk_words[i - 15].rotate_right(7))
                ^ (chunk_words[i - 15].rotate_right(18))
                ^ (chunk_words[i - 15] >> 3);
            let s1: u32 = (chunk_words[i - 2].rotate_right(17))
                ^ (chunk_words[i - 2].rotate_right(19))
                ^ (chunk_words[i - 2] >> 10);
            
            chunk_words[i] = chunk_words[i - 16] + s0 + chunk_words[i-7] + s1; 
        }

        chunk_words
    })
    .collect::<Vec<Vec<u32>>>();

    Ok(extended_chunks)
}

fn pre_processing(in_bytes: &mut Vec<u8>) -> Result<&Vec<u8>, Box<dyn Error>> {
    let in_len = in_bytes.len();

    in_bytes.push(0x80); // Append "1" bit, assuming byte aligned input

    let mut n_zero_pad_bytes: Option<u64> = None;

    if (8 * in_bytes.len() + 64) % 512 != 0 {
        n_zero_pad_bytes = Some((512 - (8 * in_bytes.len() as u64 + 64) % 512) / 8);
    }

    if let Some(nzeros) = n_zero_pad_bytes {
        (0..nzeros)
            .into_iter()
            .map(|x| in_bytes.push(0))
            .collect::<Vec<_>>();
    }

    in_bytes.extend_from_slice(&(in_len as u64).to_be_bytes());

    Ok(in_bytes)
}

fn gen_sha256(str_in: String) -> Result<String, Box<dyn Error>> {
    let mut in_vec: Vec<u8> = str_in.into_bytes();
    pre_processing(&mut in_vec);
    let ext_chunks: Vec<Vec<u32>> = get_chunks_512(&mut in_vec).unwrap();

    return Ok(String::from("OK"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_processing_len() {
        let mut in_bytes = Vec::<u8>::new();
        assert_eq!(512 / 8, pre_processing(&mut in_bytes).unwrap().len());
    }

    #[test]
    fn test_get_chunks() {
        let mut in_bytes = Vec::<u8>::new();
        for i in 0..512 {
            in_bytes.push(0);
        }
        get_chunks_512(&mut in_bytes);
    }

    #[test]
    fn test_compression() {
        let mut chunks: Vec<Vec<u32>> = Vec::<Vec::<u32>>::new();
        for i in 0..16 {
            let mut chunk = Vec::<u32>::new();
            for i in 0..64 {
                chunk.push(0);
            }

            chunks.push(chunk);
        }
        
        compression(&mut chunks);
    }
}
