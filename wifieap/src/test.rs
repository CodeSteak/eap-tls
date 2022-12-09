use self::{
    peer::{EapPeer, EapPeerResult},
    server::{EapServer, EapServerResult},
};

pub use super::*;

fn run_handshake(peer: &mut EapPeer, server: &mut EapServer) -> (EapPeerResult, EapServerResult) {
    let mut last_results = None;

    for _ in 0..100 {
        let res_server = server.step();
        if let Some(buffer) = &res_server.response {
            peer.receive(buffer);
        }

        let res_peer = peer.step();
        if let Some(buffer) = &res_peer.response {
            server.receive(buffer);
        }

        last_results = Some((res_peer.clone(), res_server.clone()));

        if res_server.status != EapStatus::Ok || res_peer.status != EapStatus::Ok {
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

    let mut server = EapServer::buider()
        .set_tls_config(TlsConfig::dummy_server())
        .allow_tls()
        .build();

    let (res_peer, res_server) = run_handshake(&mut peer, &mut server);

    assert_eq!(res_peer.status, EapStatus::Finished);
    assert_eq!(res_server.status, EapStatus::Finished);
    assert_eq!(res_peer.key_material, res_server.key_material);
}

#[test]
fn tls_handshake_with_psk() {
    let mut peer = EapPeer::builder("pskuser").set_password("psk").build();

    let mut server = EapServer::buider()
        .set_password("pskuser", "psk")
        .allow_md5()
        .build();

    let (res_peer, res_server) = run_handshake(&mut peer, &mut server);

    assert_eq!(res_peer.status, EapStatus::Finished);
    assert_eq!(res_server.status, EapStatus::Finished);
}
