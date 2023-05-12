use std::net::{TcpStream};
use std::io::{Read, Write};
use std::str::from_utf8;
use std::env;

fn main() {

    let args: Vec<String> = env::args().collect();
    let msg = args[1..].join(" ") + "\n";

    match TcpStream::connect("localhost:4711") {
        Ok(mut stream) => {
            stream.write_all(msg.as_bytes()).unwrap();
            stream.flush().unwrap();

            let mut data = [0 as u8; 10000];
            match stream.read(&mut data) {
                Ok(_) => {
                    let text = from_utf8(&data).unwrap();
                    println!("{}", text);
                },
                Err(e) => {
                    println!("Failed to receive data: {}", e);
                }
            }
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
}
