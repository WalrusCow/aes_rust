mod aes;

fn main() {
    let enc_key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,];
    let block: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,];

    let cipher = aes::AES::new(&enc_key);
    let enc = cipher.encrypt_block(&block);
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
