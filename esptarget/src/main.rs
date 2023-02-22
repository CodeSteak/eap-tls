use std::time::Instant;

use eap;
use esp_idf_sys as _;

use eap::*;

fn main() {
    esp_idf_sys::link_patches();

    let mut server = Authenticator::new("password");
    let mut client = Peer::new("user", "password");

    let start = Instant::now();

    for i in 0..100 {
        println!("=== {i}");

        println!("== SERVER");
        let res_server = server.step();
        if let Some(buffer) = &res_server.response {
            hex_dump("S->P", buffer);
            client.receive(buffer);
        }

        println!("== PEER");
        let res_client = client.step();
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

    loop {}
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
