use wifieap::{peer::EapPeer, server::{EapServer, EapStatus}, server::EapServerStepResult};

fn main() {
    let mut peer = EapPeer::new();
    let mut server = EapServer::new();

    for i in 0..100 {
        println!("=== {}", i);

        let res = server.step();
        if let Some(buffer) = &res.response {
            hex_dump("S->P", buffer);
            peer.receive(buffer);
        }

        if let Some(buffer) = peer.step() {
            hex_dump("P->S", &buffer);
            server.receive(&buffer);
        }

        if res.status != EapStatus::Ok {
            eprintln!("{:?}", &res.status);
            break;
        }
    }
}

fn hex_dump(label : &str, data : &[u8]) {
    println!("{:10}", label);

    for (i, byte) in data.iter().enumerate() {
        print!("{:02x} ", byte);
        if i % 16 == 15 {
            println!();
        }
    }
    println!();
}