mod aes;

type ByteIterator = Iterator<Item=u8>;

pub struct CTR {
    aes: AES,
}

impl CTR {
    pub fn new(key: &[u8; 16]) -> CTR {
        CTR {
            aes: AES::new(&key),
        }
    }

    /// Handily, CTR encryption is the same as decryption
    fn encrypt_or_decrypt(&self, nonce: &Vec<u8>, data: &mut ByteIterator) -> CTR_Iterator {
        // Must be shorter than a block
        assert!(nonce.len() <= 16);

        let mut nonce_block = [0u8; 16];
        for (i, b) in &nonce.iter().enumerate() {
            nonce_block[i] = b;
        }

        CTR_Iterator::new(nonce_block, &data, &self.aes)
    }

    pub fn encrypt(&self, nonce: &Vec<u8>, plaintext: &mut ByteIterator) -> CTR_Iterator {
        self.encrypt_or_decrypt(&nonce, &plaintext)
    }

    pub fn decrypt(&self, nonce: &Vec<u8>, ciphertext: &mut ByteIterator) -> CTR_Iterator {
        self.encrypt_or_decrypt(&nonce, &ciphertext)
    }

}

// TODO: How to do lifetimes??
pub struct CTR_Iterator {
    data: &'a mut ByteIterator,
    nonce_block: [u8; 16],
    // This is the encrypted nonce block
    block: [u8; 16],
    // Which byte in the encrypted block to use next for the stream
    next_block_byte: usize,
    // The AES thingy to use
    aes: &'b AES,
}

impl CTR_Iterator {
    fn new(nonce_block: [u8; 16], data: &'a mut ByteIterator, aes: &'b AES) -> CTR_Iterator {
        CTR_Iterator {
            data: &data,
            nonce_block: nonce_block,
            block: [0u8; 16],
            next_block_byte: 0,
            aes: &aes,
        }
    }

    // TODO: Here are some ideas, we need to test it thoroughly lol
    fn increment_nonce_block(&mut self) {
        /*
        // Do magic things
        if let Some((i, b)) = nonce_block.iter_mut().enumerate().rev().skip_while(|x| x == 0xff).next() {
            // We matched
            *b += 1;
            for j in i+1..16 {
                nonce_block[j] = 0;
            }
        }
        else {
            // The whole block is 0xff
            for b in nonce_block.iter_mut() {
                *b = 0;
            }
        }

        for i in (0..16).rev() {
            if nonce_block[i] != 0xff {
                nonce_block[i] += 1;
                for j in (i + 1)..16 {
                    nonce_block[j] = 0;
                }
                break
            } else if i == 15 {
                // Everything was 0xff
                for j in 0..16 {
                    nonce_block[j] = 0;
                }
            }
        }
        */
    }
}

impl Iterator for CTR_Iterator {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.next_block_byte == 16 {
            // We must encrypt the next block.
            // Increment nonce by one, encrypt it under the aes key
            self.increment_nonce_block();
            self.block = self.aes.encrypt_block(&self.nonce_block);
            self.next_block_byte = 0;
        }

        if let Some(next_byte) = data.next() {
            self.next_block_byte += 1;
            Some(next_byte ^ block[next_block_byte - 1])
        } else {
            None
        }
    }
}
