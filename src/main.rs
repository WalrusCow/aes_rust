use std::env;

use std::fs::File;
use std::io::Read;

fn s_box() -> [u8; 256] {
    [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]
}

fn sub_bytes(block: &[u8; 16], s_box: &[u8; 256]) -> [u8; 16] {
    let mut new_block: [u8; 16] = [0; 16];
    for i in 0..16 {
        new_block[i] = s_box[block[i] as usize];
    }
    new_block
}

fn shift_rows(block: &[u8; 16]) -> [u8; 16] {
    //  0,  4,  8, 12
    //  1,  5,  9, 13
    //  2,  6, 10, 14
    //  3,  7, 11, 15
    let mut new_block: [u8; 16] = [0; 16];
    for row in 0..4 {
        for col in 0..4 {
            let old_idx = col * 4 + row;
            let new_idx = (16 + old_idx - row * 4) % 16;
            new_block[new_idx] = block[old_idx];
        }
    }
    new_block
}

fn mix_columns(block: &[u8; 16]) -> [u8; 16] {
    //  0,  4,  8, 12
    //  1,  5,  9, 13
    //  2,  6, 10, 14
    //  3,  7, 11, 15
    let dbl = |x: u8| -> u8 {
        if x & 0x80 == 0x80 {
            x << 1
        } else {
            (x << 1) ^ 0x1b
        }
    };
    let mut new_block = [0u8; 16];
    for col in 0..4 {
        let a0 = block[col * 4];
        let a1 = block[col * 4 + 1];
        let a2 = block[col * 4 + 2];
        let a3 = block[col * 4 + 3];
        new_block[col * 4] = dbl(a0) ^ dbl(a1) ^ a1 ^ a2 ^ a3;
        new_block[col * 4 + 1] = a0 ^ dbl(a1) ^ dbl(a2) ^ a2 ^ a3;
        new_block[col * 4 + 2] = a0 ^ a1 ^ dbl(a2) ^ dbl(a3) ^ a3;
        new_block[col * 4 + 3] = dbl(a0) ^ a0 ^ a1 ^ a2 ^ dbl(a3);
    }
    new_block
}

/// 128 bit key only
fn encrypt_block(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let xor_blocks = |b1: &[u8; 16], b2: &[u8; 16]| -> [u8; 16] {
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = b1[i] ^ b2[i];
        }
        result
    };

    let round_keys = key_schedule(key);
    let sbox = s_box();

    let mut state = xor_blocks(block, &round_keys[0]);

    for i in 1..10 {
        state = sub_bytes(&state, &sbox);
        state = shift_rows(&state);
        state = mix_columns(&state);
        state = xor_blocks(&state, &round_keys[i]);
    }
    state = shift_rows(&sub_bytes(&state, &sbox));
    xor_blocks(&state, &round_keys[10])
}

/// Do 128 bit AES key schedule
fn key_schedule(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let sb = s_box();

    let xor_words = |a: &[u8], b: &[u8]| -> [u8; 4] {
        assert_eq!(a.len(), 4);
        assert_eq!(b.len(), 4);
        [
            a[0] ^ b[0],
            a[1] ^ b[1],
            a[2] ^ b[2],
            a[3] ^ b[3],
        ]
    };

    let mut round_keys: [[u8; 16]; 11] = [[0; 16]; 11];
    // Copy the original key as the first round key
    for i in 0..16 {
        round_keys[0][i] = key[i];
    }

    let masks: [u8; 11] = [
        0x00, // unused, for convenience
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36,
    ];


    // We need to generate 10 more round keys
    for round in 1..11 {
        let round_fn = |key: &[u8]| -> [u8; 4] {
            [
                sb[key[1] as usize] ^ masks[round],
                sb[key[2] as usize],
                sb[key[3] as usize],
                sb[key[0] as usize],
            ]
        };

        for word in 0..4 {
            // s for start, which byte to start the word at
            let s = word * 4;

            // First word is a little special, we apply the round function
            let new_bytes = if word == 0 {
                let last_word = round_fn(&round_keys[round - 1][12..16]);
                xor_words(&round_keys[round - 1][s..s+4], &last_word)
            } else {
                let last_word = &round_keys[round][s-4..s];
                xor_words(&round_keys[round - 1][s..s+4], last_word)
            };

            for (i, byte) in new_bytes.iter().enumerate() {
                round_keys[round][s + i] = *byte;
            }
        }
    }
    round_keys
}

fn main() {

    let enc_key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,];
    let block: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,];

    let enc = encrypt_block(&block, &enc_key);
    for byte in enc.iter() {
        print!("{:0>2x}", byte);
    }
    print!("\n");

    //let args: Vec<String> = env::args().collect();
    //let file_path = &args[1];
    //let mut file_handle = match File::open(file_path) {
    //    Ok(fh) => fh,
    //    Err(_) => {
    //        println!("Could not open file {}", file_path);
    //        return;
    //    },
    //};
    //let mut buf: [u8; 4096] = [0; 4096];
    //let bytes_read = match file_handle.read(&mut buf) {
    //    Ok(count) => count,
    //    Err(_) => {
    //        println!("Error reading file.");
    //        return;
    //    },
    //};
    //println!("Read {} bytes", bytes_read);
}
