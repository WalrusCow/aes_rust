use aes::AES;

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
    fn encrypt_or_decrypt<'data, 'own>(
        &'own self,
        nonce: &Vec<u8>,
        data: &'data mut ByteIterator
    ) -> CTR_Iterator<'data, 'own> {
        // Must be shorter than a block
        assert!(nonce.len() <= 16);

        let mut nonce_block = [0u8; 16];
        for (i, b) in nonce.iter().enumerate() {
            nonce_block[i] = *b;
        }

        CTR_Iterator::new(nonce_block, &mut data, &self.aes)
    }

    pub fn encrypt<'data, 'own>(
        &'own self,
        nonce: &Vec<u8>,
        plaintext: &'data mut ByteIterator
    ) -> CTR_Iterator<'data, 'own> {
        self.encrypt_or_decrypt(&nonce, &mut plaintext)
    }

    pub fn decrypt<'data, 'own>(
        &'own self,
        nonce: &Vec<u8>,
        ciphertext: &'data mut ByteIterator
    ) -> CTR_Iterator<'data, 'own> {
        self.encrypt_or_decrypt(&nonce, &mut ciphertext)
    }

}

// TODO: How to do lifetimes??
pub struct CTR_Iterator<'caller, 'parent> {
    data: &'caller mut ByteIterator,
    nonce_block: [u8; 16],
    // This is the encrypted nonce block
    block: [u8; 16],
    // Which byte in the encrypted block to use next for the stream
    next_block_byte: usize,
    // The AES thingy to use
    aes: &'parent AES,
}

impl<'caller, 'parent> CTR_Iterator<'caller, 'parent> {
    fn new<'c, 'p>(
        nonce_block: [u8; 16],
        data: &'c mut ByteIterator,
        aes: &'p AES
    ) -> CTR_Iterator<'c, 'p> {
        CTR_Iterator {
            data: &mut data,
            nonce_block: nonce_block,
            block: [0u8; 16],
            next_block_byte: 0,
            aes: &aes,
        }
    }
}

impl<'caller, 'parent> Iterator for CTR_Iterator<'caller, 'parent> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.next_block_byte == 16 {
            // We must encrypt the next block.
            // Increment nonce by one, encrypt it under the aes key
            increment_byte_array(&mut self.nonce_block);
            self.block = self.aes.encrypt_block(&self.nonce_block);
            self.next_block_byte = 0;
        }

        if let Some(next_byte) = self.data.next() {
            self.next_block_byte += 1;
            Some(next_byte ^ self.block[self.next_block_byte - 1])
        } else {
            None
        }
    }
}

fn increment_byte_array(byte_array: &mut [u8]) -> () {
    // Start at len and go to zero to avoid negative overflow on usize
    let mut idx = byte_array.len();
    while idx > 0 && byte_array[idx - 1] == 0xff {
        byte_array[idx - 1] = 0;
        idx -= 1;
    }
    if idx != 0 {
        byte_array[idx - 1] += 1;
    }
}

// Tests for private function
#[cfg(test)]
#[test]
fn short_array_increment() {
    let mut arr = [0u8];
    increment_byte_array(&mut arr);
    assert_eq!(arr, [1u8]);
}

#[cfg(test)]
#[test]
fn short_array_increment_overflow() {
    let mut arr = [0xffu8];
    increment_byte_array(&mut arr);
    assert_eq!(arr, [0u8]);
}

#[cfg(test)]
#[test]
fn long_array_increment() {
    let mut arr = [1u8, 0xffu8];
    increment_byte_array(&mut arr);
    assert_eq!(arr, [2u8, 0u8]);
}

#[cfg(test)]
#[test]
fn long_array_increment_overflow() {
    let mut arr = [0xffu8, 0xffu8, 0xffu8];
    increment_byte_array(&mut arr);
    assert_eq!(arr, [0u8, 0u8, 0u8]);
}
