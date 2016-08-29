use aes::AES;

pub struct CTR {
    aes: AES,
}

impl CTR {
    pub fn new(key: &[u8; 16]) -> CTR {
        CTR {
            aes: AES::new(&key),
        }
    }

    pub fn get_stream(&self, nonce: &[u8]) -> CtrByteStream {
        CtrByteStream::new(&self.aes, &nonce)
    }
}

pub struct CtrByteStream<'parent> {
    // AES encryption (with key)
    aes: &'parent AES,
    // The nonce block we encrypted for this stage
    nonce_block: [u8; 16],
    // Nonce after being run through AES
    encrypted_nonce: [u8; 16],
    // Which byte in the encrypted nonce block to use next for the stream
    next_block_byte: usize,
    // How many times we have incremented the nonce block
    block_counter: usize,
}

impl<'parent> CtrByteStream<'parent> {
    fn new<'p>(aes: &'p AES, nonce: &[u8]) -> CtrByteStream<'p> {
        // Must be shorter than a block
        assert!(nonce.len() <= 16);

        let mut nonce_block = [0u8; 16];
        for (i, b) in nonce.iter().enumerate() {
            nonce_block[i] = *b;
        }

        CtrByteStream {
            aes: &aes,
            encrypted_nonce: aes.encrypt_block(&nonce_block),
            nonce_block: nonce_block,
            next_block_byte: 0,
            block_counter: 0,
        }
    }

    pub fn encrypt_byte(&mut self, byte: u8) -> u8 {
        if self.next_block_byte >= 16 {
            increment_byte_array(&mut self.nonce_block);
            self.encrypted_nonce = self.aes.encrypt_block(&self.nonce_block);
            self.next_block_byte = 0;
            self.block_counter += 1;
        }

        let res = self.encrypted_nonce[self.next_block_byte] ^ byte;
        self.next_block_byte += 1;
        res
    }
}

fn increment_byte_array(byte_array: &mut [u8]) {
    for v in byte_array.iter_mut().rev() {
        let (ans, overflow) = v.overflowing_add(1);
        *v = ans;

        if !overflow {
            break;
        }
    }
}

// Tests for private function
#[cfg(test)]
#[test]
fn array_increment() {
    let mut arr = [0u8];
    increment_byte_array(&mut arr);
    assert_eq!(arr, [1u8]);

    let mut arr = [0xffu8];
    increment_byte_array(&mut arr);
    assert_eq!(arr, [0u8]);

    let mut arr = [1u8, 0xffu8];
    increment_byte_array(&mut arr);
    assert_eq!(arr, [2u8, 0u8]);

    let mut arr = [0xffu8, 0xffu8, 0xffu8];
    increment_byte_array(&mut arr);
    assert_eq!(arr, [0u8, 0u8, 0u8]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctr_stream_works() {
        let key: [u8; 16] = [
            0xa6, 0x1f, 0x9b, 0x80, 0xc7, 0x39, 0x1e, 0x74,
            0x01, 0xa9, 0x48, 0xd1, 0x03, 0x8b, 0x73, 0x46,
        ];
        let nonce: Vec<u8> = vec![
            0x51, 0x03, 0x8c, 0xd6, 0x47, 0xab, 0xe8, 0x47,
            0xf6, 0x2b, 0xdf, 0xae, 0x35, 0xd7, 0x01, 0x93,
        ];
        let data: [u8; 16] = [
            0x53, 0x69, 0x78, 0x74, 0x65, 0x65, 0x6e, 0x20,
            0x6c, 0x65, 0x74, 0x74, 0x65, 0x72, 0x73, 0x21,
        ];

        let mut result: [u8; 16] = [0; 16];

        let expected: [u8; 16] = [
            0x95, 0x6b, 0xea, 0xea, 0xfd, 0x14, 0x54, 0x8b,
            0x7a, 0xa6, 0x43, 0x56, 0xcd, 0x9c, 0x1b, 0x61,
        ];


        let c = CTR::new(&key);
        // Encrypt
        let mut stream = c.get_stream(&nonce);
        for (i, d) in data.iter().enumerate() {
            result[i] = stream.encrypt_byte(*d);
        }
        assert_eq!(result, expected);

        // Now "decrypt"
        let mut stream = c.get_stream(&nonce);
        for (i, d) in expected.iter().enumerate() {
            result[i] = stream.encrypt_byte(*d);
        }
        assert_eq!(result, data);
    }
}
