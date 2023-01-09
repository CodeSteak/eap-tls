use eap::{Authenticator, AuthenticatorStepStatus};
use wifieap::{peer::EapPeer, server::EapServer, EapStatus, TlsConfig};

fn main() {
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
    let mut peer = EapPeer::builder("user")
        //.set_tls_config(TlsConfig::dummy_client())
        .set_password("42")
        .build();

    let mut server = EapServer::buider()
        .set_tls_config(TlsConfig::dummy_server())
        .allow_tls()
        .set_password("user", "42")
        .allow_md5()
        .build();

    for i in 0..100 {
        println!("=== {i}");

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
