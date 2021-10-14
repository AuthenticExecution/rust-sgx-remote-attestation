use std::net::{TcpListener, TcpStream};
use std::{thread, time};

use sgx_crypto::tls_psk::*;

use std::io::{Write, Read};

const PORT : u16 = 8439;

fn client(psk: &[u8; 16]) {
    thread::sleep( time::Duration::from_millis(1000));
    let conn = TcpStream::connect(("127.0.0.1", PORT)).unwrap();

    let mut ctx = new_client_context(psk, conn).unwrap();
    let data = b"ciao";
    ctx.write(data).unwrap();
}

fn server(psk: &[u8; 16]) {
    let listener = TcpListener::bind(("127.0.0.1", PORT)).unwrap();
    let conn = listener.accept().unwrap().0;

    let mut ctx = new_server_context(psk, conn).unwrap();
    let mut buf = [0u8; 4];
    ctx.read_exact(&mut buf).unwrap();

    assert_eq!(&buf, b"ciao");
}

#[cfg(unix)]
mod test {
    use std::thread;

    #[test]
    fn test_tls() {
        let key = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];

        let s = thread::spawn(move || super::server(&key));
        let c = thread::spawn(move || super::client(&key));
        c.join().unwrap();
        s.join().unwrap();
    }
}
