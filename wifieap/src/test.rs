use self::{peer::EapPeer, server::EapServer};

pub use super::*;
use common::*;

fn run_handshake(
    peer: &mut Box<EapPeer>,
    server: &mut Box<EapServer>,
) -> (OwnedEapStepResult, OwnedEapStepResult) {
    let mut last_results = None;

    for _ in 0..100 {
        let res_server = server.step().into_owned();
        if let Some(buffer) = &res_server.response {
            peer.receive(buffer);
        }

        let res_peer = peer.step().into_owned();
        if let Some(buffer) = &res_peer.response {
            server.receive(buffer);
        }

        last_results = Some((res_peer.clone(), res_server.clone()));

        if res_server.status != EapStepStatus::Ok || res_peer.status != EapStepStatus::Ok {
            break;
        }
    }

    last_results.unwrap()
}

#[test]
fn tls_handshake() {
    let mut peer = EapPeer::builder("user")
        .set_tls_config(TlsConfig::dummy_client())
        .build();

    let mut server = EapServer::builder()
        .set_tls_config(TlsConfig::dummy_server())
        .allow_tls()
        .build();

    let (res_peer, res_server) = run_handshake(&mut peer, &mut server);

    assert_eq!(res_peer.status, EapStepStatus::Finished);
    assert_eq!(res_server.status, EapStepStatus::Finished);
}

#[test]
fn tls_handshake_failing() {
    let mut peer = EapPeer::builder("user").set_password("Hello World").build();

    let mut server = EapServer::builder()
        .set_tls_config(TlsConfig::dummy_server())
        .allow_tls()
        .build();

    let (res_peer, res_server) = run_handshake(&mut peer, &mut server);

    assert_eq!(res_peer.status, EapStepStatus::Error);
    assert_eq!(res_server.status, EapStepStatus::Error);
}

#[test]
fn handshake_with_psk() {
    let mut peer = EapPeer::builder("pskuser").set_password("psk").build();

    let mut server = EapServer::builder()
        .set_password("pskuser", "psk")
        .allow_md5()
        .build();

    let (res_peer, res_server) = run_handshake(&mut peer, &mut server);

    assert_eq!(res_peer.status, EapStepStatus::Finished);
    assert_eq!(res_server.status, EapStepStatus::Finished);
}

#[test]
fn handshake_with_psk_failing() {
    let mut peer = EapPeer::builder("user").set_password("password").build();

    let mut server = EapServer::builder()
        .set_password("not this one", "123456")
        .allow_md5()
        .build();

    let (res_peer, res_server) = run_handshake(&mut peer, &mut server);

    assert_eq!(res_peer.status, EapStepStatus::Error);
    assert_eq!(res_server.status, EapStepStatus::Error);
}
