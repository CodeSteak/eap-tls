use wifieap::{
    peer::EapPeer,
    server::EapServer,
    util::EapStatus,
};

fn main() {
    let mut peer = EapPeer::new();
    let mut server = EapServer::new();

    for i in 0..100 {
        println!("=== {}", i);

        let res_server = server.step();
        if let Some(buffer) = &res_server.response {
            hex_dump("S->P", buffer);
            peer.receive(buffer);
        }

        if let Some(mat) = &res_server.key_material {
            hex_dump("S Key: ", mat);
        }

        let res_peer = peer.step();
        if let Some(buffer) = &res_peer.response {
            hex_dump("P->S", &buffer);
            server.receive(&buffer);
        }

        if let Some(mat) = &res_peer.key_material {
            hex_dump("P Key: ", mat);
        }

        if res_server.status != EapStatus::Ok || res_peer.status != EapStatus::Ok {
            eprintln!("peer {:?} server {:?}", &res_peer.status, &res_server.status);
            break;
        }
    }
}

fn hex_dump(label: &str, data: &[u8]) {
    println!("{:10}", label);

    for line in data.chunks(16) {
        for byte in line {
            print!("{:02x} ", byte);
        }
        print!(" | ");

        for byte in line {
            if *byte >= 32 && *byte < 127 {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }

        println!();
    }
}
