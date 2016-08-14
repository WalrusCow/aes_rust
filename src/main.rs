use std::env;
use std::fs::File;
use std::io::Read;
use std::io::Write;

mod aes;
mod ctr;

fn main() {
    let key: [u8; 16] = [
        0xa6, 0x1f, 0x9b, 0x80, 0xc7, 0x39, 0x1e, 0x74,
        0x01, 0xa9, 0x48, 0xd1, 0x03, 0x8b, 0x73, 0x46,
    ];
    let nonce: Vec<u8> = vec![
        0x51, 0x03, 0x8c, 0xd6, 0x47, 0xab, 0xe8, 0x47,
        0xf6, 0x2b, 0xdf, 0xae, 0x35, 0xd7, 0x01, 0x93,
    ];

    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    let mut file_handle = match File::open(file_path) {
        Ok(fh) => fh,
        Err(_) => {
            println!("Could not open file {}", file_path);
            return;
        },
    };

    let mut write_handle = match File::create("./awtpoot") {
        Ok(f) => f,
        Err(e) => {
            println!("Fuck {}", e);
            return;
        },
    };

    let mut buf: [u8; 4096] = [0; 4096];

    let ctr_thing = ctr::CTR::new(&key);
    let mut stream = ctr_thing.get_stream(&nonce);

    loop {
        let bytes_read = match file_handle.read(&mut buf) {
            Ok(count) => count,
            Err(_) => {
                println!("Error reading file.");
                return;
            },
        };

        if bytes_read == 0 {
            println!("Doooone");
            break;
        } else {
            for b in buf.iter_mut().take(bytes_read) {
                *b = stream.encrypt_byte(*b);
            }
            write_handle.write_all(&buf[..bytes_read]);
        }
    }
}
