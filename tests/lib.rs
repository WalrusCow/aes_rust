extern crate aes;

#[test]
fn ctr_stream() {
    let data = vec![5u8, 7u8, 10u8];
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let ctr = aes::CTR::new(&key);
    let mut stream = ctr.get_stream(&nonce);

    let mut res: Vec<u8> = Vec::new();
    for d in data.iter() {
        res.push(stream.encrypt_byte(*d));
    }

    let mut stream = ctr.get_stream(&nonce);
    for (i, r) in res.iter().enumerate() {
        assert_eq!(data[i], stream.encrypt_byte(*r));
    }
}
