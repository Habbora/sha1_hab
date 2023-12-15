pub fn sha1(input: &[u8]) -> [u8; 20] {
    let bytes: Vec<u8> = input
        .iter()
        .cloned()
        .chain(std::iter::once(0x80))
        .chain(std::iter::repeat(0x00).take({
            let mut cont = (((input.len() / 64) + 1) * 64) - input.len();
            if cont < 9 {
                cont = 64 - (9 - cont);
            } else {
                cont = cont - 9;
            }
            cont
        }))
        .chain(std::iter::once(((input.len() * 8) >> 56) as u8))
        .chain(std::iter::once(((input.len() * 8) >> 48) as u8))
        .chain(std::iter::once(((input.len() * 8) >> 40) as u8))
        .chain(std::iter::once(((input.len() * 8) >> 32) as u8))
        .chain(std::iter::once(((input.len() * 8) >> 24) as u8))
        .chain(std::iter::once(((input.len() * 8) >> 16) as u8))
        .chain(std::iter::once(((input.len() * 8) >> 8) as u8))
        .chain(std::iter::once((input.len() * 8) as u8))
        .collect();

    let blocks: Vec<Vec<u8>> = bytes.chunks_exact(64).map(|item| item.to_vec()).collect();

    let sum = |a: &u32, b: &u32| {
        let a = a.clone() as u64 + b.clone() as u64;
        a as u32
    };

    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    for (_i, item) in blocks.iter().enumerate() {
        let mut word: Vec<u32> = item
            .chunks_exact(4)
            .map(|chunk| {
                let mut bytes = [0; 4];
                bytes.copy_from_slice(chunk);
                u32::from_be_bytes(bytes)
            })
            .collect();

        for i in 16..80 {
            let new_word = word[i - 3] ^ word[i - 8] ^ word[i - 14] ^ word[i - 16];
            let new_word = new_word.rotate_left(1);
            word.push(new_word);
        }

        let w = |i: usize| word[i].clone();

        let f = |t: usize, b: u32, c: u32, d: u32| match t {
            0..=19 => (b & c) | (!b & d),
            20..=39 => b ^ c ^ d,
            40..=59 => (b & c) | (b & d) | (c & d),
            60..=79 => b ^ c ^ d,
            _ => panic!("Valor de t fora do intervalo válido para SHA-1"),
        };

        let k = |t: usize| match t {
            0..=19 => 0x5A827999 as u32,
            20..=39 => 0x6ED9EBA1 as u32,
            40..=59 => 0x8F1BBCDC as u32,
            60..=79 => 0xCA62C1D6 as u32,
            _ => panic!("Valor de t fora do intervalo válido para SHA-1"),
        };

        let mut a: u32 = h0;
        let mut b: u32 = h1;
        let mut c: u32 = h2;
        let mut d: u32 = h3;
        let mut e: u32 = h4;

        for i in 0..80 {
            let temp = a.rotate_left(5) as u64
                + f(i, b, c, d) as u64
                + e as u64
                + w(i) as u64
                + k(i) as u64;

            e = d.clone();
            d = c.clone();
            c = b.rotate_left(30).clone();
            b = a.clone();
            a = temp as u32;
        }

        h0 = sum(&h0, &a);
        h1 = sum(&h1, &b);
        h2 = sum(&h2, &c);
        h3 = sum(&h3, &d);
        h4 = sum(&h4, &e);
    }

    let result: Vec<u8> = vec![
        h0.to_be_bytes().to_vec(),
        h1.to_be_bytes().to_vec(),
        h2.to_be_bytes().to_vec(),
        h3.to_be_bytes().to_vec(),
        h4.to_be_bytes().to_vec(),
    ]
    .concat();

    let mut r: [u8; 20] = [0; 20];
    r.copy_from_slice(&result);
    r
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn it_works() {
        let input = "bom dia";
        let aux: Vec<u8> = vec![101, 70, 62, 230, 100, 171, 181, 195, 91, 218, 39, 19, 179, 148, 203, 251, 10, 157, 243, 165];
        let mut expect: [u8; 20] = [0u8; 20];
        expect.copy_from_slice(&aux);
        let result = sha1(input.as_bytes());
        assert_eq!(result, expect);
    }
}
