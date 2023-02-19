use eap::{Authenticator, AuthenticatorStepStatus};
use wifieap::{peer::EapPeer, server::EapServer, EapStatus, TlsConfig};

fn main() {
    let arg = std::env::args().nth(1).unwrap_or("a".to_string());

    match arg.as_str() {
        "a" => own_impl_tls(),
        "b" => own_impl_main(),
        "c" => main_peer_server_orig(),
        _ => panic!("Unknown argument"),
    }
}

fn own_impl_tls() {
    let mut peer = EapPeer::builder("user")
        .set_tls_config(TlsConfig::dummy_client())
        .build();

    let mut server = Authenticator::new_tls();

    for i in 0..100 {
        println!("=== {i}");

        let res_server = server.step();
        if let Some(buffer) = &res_server.response {
            hex_dump("S->P", buffer);
            peer.receive(buffer);
        }

        //if let Some(mat) = &res_server.key_material {
        //    hex_dump("S Key: ", mat);
        //}

        let res_peer = peer.step();
        if let Some(buffer) = &res_peer.response {
            hex_dump("P->S", buffer);
            server.receive(buffer);
        }

        if let Some(mat) = &res_peer.key_material {
            hex_dump("P Key: ", mat);
        }

        if res_server.status != AuthenticatorStepStatus::Ok || res_peer.status != EapStatus::Ok {
            eprintln!(
                "peer {:?} server {:?}",
                &res_peer.status, &res_server.status
            );
            break;
        }
    }
}

fn own_impl_main() {
    let mut peer = EapPeer::builder("user")
        //.set_tls_config(TlsConfig::dummy_client())
        .set_password("42")
        .build();

    let mut server = Authenticator::new("42");

    for i in 0..100 {
        println!("=== {i}");

        let res_server = server.step();
        if let Some(buffer) = &res_server.response {
            hex_dump("S->P", buffer);
            peer.receive(buffer);
        }

        //if let Some(mat) = &res_server.key_material {
        //    hex_dump("S Key: ", mat);
        //}

        let res_peer = peer.step();
        if let Some(buffer) = &res_peer.response {
            hex_dump("P->S", buffer);
            server.receive(buffer);
        }

        if let Some(mat) = &res_peer.key_material {
            hex_dump("P Key: ", mat);
        }

        if res_server.status != AuthenticatorStepStatus::Ok || res_peer.status != EapStatus::Ok {
            eprintln!(
                "peer {:?} server {:?}",
                &res_peer.status, &res_server.status
            );
            break;
        }
    }
}

fn main_peer_server_orig() {
    println!("=== INIT PEER");
    let mut peer = EapPeer::builder("user")
        .set_tls_config(TlsConfig::dummy_client())
        //.set_password("42")
        .build();

    println!("=== INIT SERVER");
    let mut server = EapServer::buider()
        .set_tls_config(TlsConfig::dummy_server())
        .allow_tls()
        //.set_password("user", "42")
        //.allow_md5()
        .build();

    for i in 0..100 {
        println!("=== {i}");

        println!("== SERVER");
        let res_server = server.step();
        println!("== END SERVER");

        if let Some(buffer) = &res_server.response {
            hex_dump("S->P", buffer);
            peer.receive(buffer);
        }

        if let Some(mat) = &res_server.key_material {
            hex_dump("S Key: ", mat);
        }

        println!("== PEER");
        let res_peer = peer.step();
        println!("== END PEER");
        if let Some(buffer) = &res_peer.response {
            hex_dump("P->S", buffer);
            server.receive(buffer);
        }

        if let Some(mat) = &res_peer.key_material {
            hex_dump("P Key: ", mat);
        }

        if res_server.status != EapStatus::Ok || res_peer.status != EapStatus::Ok {
            eprintln!(
                "peer {:?} server {:?}",
                &res_peer.status, &res_server.status
            );
            break;
        }
    }
}

fn hex_dump(label: &str, data: &[u8]) {
    println!("{label:10}");

    for line in data.chunks(16) {
        for byte in line {
            print!("{byte:02x} ",);
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
