use common::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{Authenticator, Peer};

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq)]
struct ExtraOptions {
    allow_timeout: bool,
}

impl ExtraOptions {
    fn wpa_does_not_give_up() -> Self {
        Self {
            allow_timeout: true,
        }
    }
}

#[track_caller]
fn run<A: EapWrapper, B: EapWrapper>(
    mut peer: B,
    mut auth: A,
    extra: Option<ExtraOptions>,
) -> (EapStepStatus, EapStepStatus) {
    let ExtraOptions { allow_timeout } = extra.unwrap_or_default();

    for _ in 0..25 {
        let EapStepResult {
            status: auth_status,
            response: auth_response,
        } = auth.step();
        let auth_response = auth_response.map(|m| m.to_vec());

        if let Some(response) = auth_response {
            hex_dump("Auth -> Peer", &response);
            peer.receive(&response);
        }

        let EapStepResult {
            status: peer_status,
            response: peer_response,
        } = peer.step();
        let peer_response = peer_response.map(|m| m.to_vec());

        if let Some(response) = peer_response {
            hex_dump("Peer -> Auth", &response);
            auth.receive(&response);
        }

        println!("peer_status={peer_status:?} auth_status={auth_status:?}");
        println!("\n\n");

        if peer_status != EapStepStatus::Ok && auth_status != EapStepStatus::Ok {
            return (peer_status, auth_status);
        }
    }

    // WPA Supplicant will never give up
    if allow_timeout {
        return (EapStepStatus::Error, EapStepStatus::Error);
    }

    panic!("Too many iterations");
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

#[test]
fn own_md5() {
    // Right Password
    let peer = Peer::new_password("hans", "1234");
    let auth = Authenticator::new_password("1234");

    assert_eq!(
        run(peer, auth, None,),
        (EapStepStatus::Finished, EapStepStatus::Finished)
    );

    // Wrong Password
    let peer = Peer::new_password("hans", "1234");
    let auth = Authenticator::new_password("not 1234");

    assert_eq!(
        run(peer, auth, None),
        (EapStepStatus::Error, EapStepStatus::Error)
    )
}

#[test]
fn own_tls() {
    // Positive
    let peer = Peer::new_tls("hans", dummycert::TlsConfig::dummy_client_rsa());
    let auth = Authenticator::new_tls(dummycert::TlsConfig::dummy_server_rsa());

    assert_eq!(
        run(peer, auth, None),
        (EapStepStatus::Finished, EapStepStatus::Finished)
    );

    // Negative
    // These Cert use different CA's
    let peer = Peer::new_tls("hans", dummycert::TlsConfig::dummy_client_rsa());
    let auth = Authenticator::new_tls(dummycert::TlsConfig::dummy_server_ed25519());
    assert_eq!(
        run(peer, auth, None),
        (EapStepStatus::Error, EapStepStatus::Error)
    );
}

#[test]
fn own_vs_wpa_md5() {
    println!("Own Peer vs WPA Authenticator");
    let peer = Peer::new_password("hans", "1234");
    let auth = wifieap::server::EapServer::new_password("hans", "1234");

    assert_eq!(
        run(peer, auth, None),
        (EapStepStatus::Finished, EapStepStatus::Finished)
    );

    // reverse role
    println!("Own Authenticator vs WPA Peer");
    let peer = wifieap::peer::EapPeer::new_password("hans", "1234");
    let auth = Authenticator::new_password("1234");

    assert_eq!(
        run(peer, auth, None),
        (EapStepStatus::Finished, EapStepStatus::Finished)
    );

    // Negative
    println!("Own Peer vs WPA Authenticator; Negative");
    let peer = Peer::new_password("hans", "1234");
    let auth = wifieap::server::EapServer::new_password("hans", "not 1234");

    assert_eq!(
        run(peer, auth, Some(ExtraOptions::wpa_does_not_give_up())),
        (EapStepStatus::Error, EapStepStatus::Error)
    );

    // Negative everse role
    println!("Own Authenticator vs WPA Peer; Negative");
    let peer = wifieap::peer::EapPeer::new_password("hans", "1234");
    let auth = Authenticator::new_password("not 1234");

    assert_eq!(
        run(peer, auth, Some(ExtraOptions::wpa_does_not_give_up())),
        (EapStepStatus::Error, EapStepStatus::Error)
    );
}

#[test]
fn own_vs_wpa_tls() {
    // Positive
    println!("Own Peer vs WPA Authenticator");
    let peer = Peer::new_tls("hans", dummycert::TlsConfig::dummy_client_rsa());
    let auth = wifieap::server::EapServer::new_tls(dummycert::TlsConfig::dummy_server_rsa());

    assert_eq!(
        run(peer, auth, None),
        (EapStepStatus::Finished, EapStepStatus::Finished)
    );

    // reverse
    println!("Own Authenticator vs WPA Peer");
    let peer = wifieap::peer::EapPeer::new_tls("hans", dummycert::TlsConfig::dummy_client_rsa());
    let auth = Authenticator::new_tls(dummycert::TlsConfig::dummy_server_rsa());

    assert_eq!(
        run(peer, auth, None),
        (EapStepStatus::Finished, EapStepStatus::Finished)
    );

    // Negative
    // These Cert use different CA's
    println!("Own Peer vs WPA Authenticator; Negative");
    let peer = Peer::new_tls("hans", dummycert::TlsConfig::dummy_client_rsa());
    let auth = wifieap::server::EapServer::new_tls(dummycert::TlsConfig::dummy_server_ed25519());

    assert_eq!(
        run(peer, auth, Some(ExtraOptions::wpa_does_not_give_up())),
        (EapStepStatus::Error, EapStepStatus::Error)
    );

    // reverse
    println!("Own Authenticator vs WPA Peer; Negative");
    let peer = wifieap::peer::EapPeer::new_tls("hans", dummycert::TlsConfig::dummy_client_rsa());
    let auth = Authenticator::new_tls(dummycert::TlsConfig::dummy_server_ed25519());

    assert_eq!(
        run(peer, auth, Some(ExtraOptions::wpa_does_not_give_up())),
        (EapStepStatus::Error, EapStepStatus::Error)
    );
}
