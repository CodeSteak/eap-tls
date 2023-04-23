use std::time::Instant;

use eap::{Authenticator, AuthenticatorStepStatus, EapWrapper, PeerStepStatus};
use wifieap::{peer::EapPeer, server::EapServer, TlsConfig};

use common::*;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or("0".to_string());

    match arg.as_str() {
        "0" => own_impl_tls_server(),
        "1" => own_impl_tls_client(),
        "2" => own_impl_tls_both(),
        "b" => own_impl_main(),
        "c" => main_peer_server_orig(),
        _ => panic!("Unknown argument"),
    }
}

fn own_impl_tls_both() {
    let mut server = Authenticator::new_tls(TlsConfig::dummy_server());
    let mut client = eap::Peer::new_tls("user", TlsConfig::dummy_client());

    let start = Instant::now();

    for i in 0..100 {
        println!("=== {i}");

        println!("== SERVER");
        let res_server = server.step().into_owned();
        if let Some(buffer) = &res_server.response {
            hex_dump("S->P", buffer);
            client.receive(buffer);
        }

        println!("== PEER");
        let res_client = client.step().into_owned();
        if let Some(buffer) = &res_client.response {
            hex_dump("P->S", buffer);
            server.receive(buffer);
        }

        if res_server.status != AuthenticatorStepStatus::Ok
            || res_client.status != PeerStepStatus::Ok
        {
            println!(
                "peer {:?} server {:?}",
                &res_client.status, &res_server.status
            );
            break;
        }
    }

    let elapsed = start.elapsed();

    println!("Elapsed: {:#?}", elapsed);
}

fn own_impl_tls_client() {
    let mut peer = eap::Peer::new_tls("user", TlsConfig::dummy_client());
    let mut server = EapServer::builder()
        .set_tls_config(TlsConfig::dummy_server())
        .allow_tls()
        //.set_password("user", "42")
        //.allow_md5()
        .build();

    for i in 0..100 {
        println!("=== {i}");

        let res_server = server.step().into_owned();
        if let Some(buffer) = &res_server.response {
            hex_dump("S->P", buffer);
            peer.receive(buffer);
        }

        //if let Some(mat) = &res_server.key_material {
        //    hex_dump("S Key: ", mat);
        //}

        let res_peer = peer.step().into_owned();
        if let Some(buffer) = &res_peer.response {
            hex_dump("P->S", buffer);
            server.receive(buffer);
        }

        if res_server.status != EapStepStatus::Ok || res_peer.status != PeerStepStatus::Ok {
            eprintln!(
                "peer {:?} server {:?}",
                &res_peer.status, &res_server.status
            );
            break;
        }
    }
}

fn own_impl_tls_server() {
    let mut peer = EapPeer::builder("user")
        .set_tls_config(TlsConfig::dummy_client())
        .build();

    let mut server = Authenticator::new_tls(TlsConfig::dummy_server());

    for i in 0..100 {
        println!("=== {i}");

        let res_server = server.step().into_owned();
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

        if res_server.status != AuthenticatorStepStatus::Ok || res_peer.status != EapStepStatus::Ok
        {
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

    let mut server = Authenticator::new_password("42");

    for i in 0..100 {
        println!("=== {i}");

        let res_server = server.step().into_owned();
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

        if res_server.status != AuthenticatorStepStatus::Ok || res_peer.status != EapStepStatus::Ok
        {
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
    let mut server = EapServer::builder()
        .set_tls_config(TlsConfig::dummy_server())
        .allow_tls()
        //.set_password("user", "42")
        //.allow_md5()
        .build();

    for i in 0..100 {
        println!("=== {i}");

        println!("== SERVER");
        let res_server = server.step().into_owned();
        println!("== END SERVER");

        if let Some(buffer) = &res_server.response {
            hex_dump("S->P", buffer);
            peer.receive(buffer);
        }

        println!("== PEER");
        let res_peer = peer.step().into_owned();
        println!("== END PEER");
        if let Some(buffer) = &res_peer.response {
            hex_dump("P->S", buffer);
            server.receive(buffer);
        }

        if res_server.status != EapStepStatus::Ok || res_peer.status != EapStepStatus::Ok {
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
