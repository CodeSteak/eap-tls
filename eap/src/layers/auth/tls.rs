use std::{sync::Arc, vec};

use rustls::{
    server::AllowAnyAuthenticatedClient, Certificate, PrivateKey, ServerConfig, ServerConnection,
};

use crate::{message::MessageContent, EapEnvironment};

use super::auth_layer::{
    AuthInnerLayer as ThisLayer, AuthInnerLayerResult as ThisLayerResult, RecvMeta,
};

const METHOD_TLS: u8 = 13;

pub struct AuthTlsMethod {
    con: ServerConnection,
    sendbufferstate: SendBufferState,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SendBufferState {
    NewPayload { total_length: usize },
    MidPayload,
}

impl Clone for AuthTlsMethod {
    fn clone(&self) -> Self {
        // Remove me after refactor
        eprintln!("ERROR: AuthTlsMethod is not clonable.");

        AuthTlsMethod::new()
    }
}

impl AuthTlsMethod {
    pub fn new() -> Self {
        let server_config = dummycert::TlsConfig::dummy_server();

        let server_cert = rustls_pemfile::read_all(&mut server_config.server_cert.as_ref())
            .unwrap()
            .into_iter()
            .flat_map(|cert| match cert {
                rustls_pemfile::Item::X509Certificate(cert) => Some(Certificate(cert)),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert!(!server_cert.is_empty());

        let server_key = rustls_pemfile::read_one(&mut server_config.server_key.as_ref())
            .unwrap()
            .and_then(|cert| match cert {
                rustls_pemfile::Item::PKCS8Key(key) => Some(PrivateKey(key)),
                _ => None,
            })
            .unwrap();

        let ca_cert = rustls_pemfile::read_all(&mut server_config.ca_cert.as_ref())
            .unwrap()
            .into_iter()
            .flat_map(|cert| match cert {
                rustls_pemfile::Item::X509Certificate(cert) => Some(Certificate(cert)),
                _ => None,
            })
            .collect::<Vec<_>>();

        let mut root_ca_store = rustls::RootCertStore::empty();

        assert!(!ca_cert.is_empty());
        for cert in ca_cert {
            root_ca_store.add(&cert).unwrap();
        }
        assert!(!root_ca_store.is_empty());

        let config = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(root_ca_store))
            .with_single_cert(server_cert, server_key)
            .expect("bad certificate/key");

        AuthTlsMethod {
            con: ServerConnection::new(Arc::new(config)).unwrap(),
            sendbufferstate: SendBufferState::MidPayload,
        }
    }
}

impl ThisLayer for AuthTlsMethod {
    fn method_identifier(&self) -> u8 {
        METHOD_TLS
    }

    fn start(&mut self, _env: &mut dyn EapEnvironment) -> ThisLayerResult {
        ThisLayerResult::Send(MessageContent {
            data: vec![Header {
                length_included: false,
                more_fragments: false,
                start: true,
            }
            .write()],
        })
    }

    fn recv(
        &mut self,
        msg: &[u8],
        _meta: &RecvMeta,
        _env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        const TLS_LEN_FIELD_LEN: usize = 4;

        if msg.is_empty() {
            return ThisLayerResult::Failed;
        }

        let header = Header::parse(msg[0]);
        let only_ack = header.more_fragments;

        let has_data = msg.len() > 1;
        if has_data {
            dbg!(header.length_included);
            let mut payload: &[u8] = if header.length_included {
                if msg.len() < TLS_LEN_FIELD_LEN + 1 {
                    eprintln!("TLS: message too short");
                    return ThisLayerResult::Failed;
                }
                &msg[(1 + TLS_LEN_FIELD_LEN)..]
            } else {
                &msg[1..]
            };

            let payload_len = payload.len();
            match self.con.read_tls(&mut payload) {
                Ok(n) if n == payload_len => { /* ok */ }
                Ok(n) => {
                    eprintln!("TLS read_tls: not all data consumed, {n} vs. {payload_len}",);
                    return ThisLayerResult::Failed;
                }
                Err(e) => {
                    eprintln!("TLS Error {e}");
                    return ThisLayerResult::Failed;
                }
            };

            match self.con.process_new_packets() {
                Ok(d) => {
                    dbg!(&d);
                    self.sendbufferstate = SendBufferState::NewPayload {
                        total_length: d.tls_bytes_to_write(),
                    }
                }
                Err(e) => {
                    eprintln!("TLS Error {e}");
                    return ThisLayerResult::Failed;
                }
            };
        }

        if !self.con.is_handshaking()
            && (matches!(
                self.sendbufferstate,
                SendBufferState::NewPayload { total_length: 0 }
            ) || matches!(self.sendbufferstate, SendBufferState::MidPayload))
        {
            return ThisLayerResult::Finished;
        }

        if !only_ack {
            const MTU: usize = 512;

            let is_first = match self.sendbufferstate {
                SendBufferState::NewPayload { .. } => true,
                SendBufferState::MidPayload => false,
            };

            let mut result = vec![0; MTU];
            let (offset, mut courser) = match self.sendbufferstate {
                SendBufferState::NewPayload { total_length } => {
                    let len = (total_length) as u32;
                    result[1..=4].copy_from_slice(&len.to_be_bytes());
                    (5, &mut result[5..])
                }
                SendBufferState::MidPayload => (1, &mut result[1..]),
            };

            match self.con.write_tls(&mut courser) {
                Ok(n) => {
                    result.truncate(n + offset);
                }
                Err(e) => {
                    eprintln!("TLS Error {e}");
                    return ThisLayerResult::Failed;
                }
            };

            let more_fragments = self.con.wants_write();
            let header = Header {
                length_included: is_first,
                more_fragments,
                start: false,
            };

            self.sendbufferstate = SendBufferState::MidPayload;

            result[0] = header.write();
            ThisLayerResult::Send(MessageContent { data: result })
        } else {
            ThisLayerResult::Send(MessageContent {
                data: vec![Header {
                    length_included: false,
                    more_fragments: false,
                    start: false,
                }
                .write()],
            })
        }
    }

    fn selectable_by_nak(&self) -> bool {
        false
    }
}

/*
https://www.rfc-editor.org/rfc/rfc5216

      0 1 2 3 4 5 6 7 8
      +-+-+-+-+-+-+-+-+
      |L M S R R R R R|
      +-+-+-+-+-+-+-+-+

      L = Length included
      M = More fragments
      S = EAP-TLS start
      R = Reserved

e.g.
0xC0 = 1100 0000
0xE0 = 1110 0000
*/

const HEADER_FIELD_LEN: u8 = 0b1000_0000;
const HEADER_FIELD_MORE_FRAGMENTS: u8 = 0b0100_0000;
const HEADER_FIELD_START: u8 = 0b0010_0000;

struct Header {
    length_included: bool,
    more_fragments: bool,
    start: bool,
}

impl Header {
    fn write(&self) -> u8 {
        let mut result = 0;
        if self.length_included {
            result |= HEADER_FIELD_LEN;
        }
        if self.more_fragments {
            result |= HEADER_FIELD_MORE_FRAGMENTS;
        }
        if self.start {
            result |= HEADER_FIELD_START;
        }
        result
    }

    fn parse(data: u8) -> Self {
        let length_included = (data & HEADER_FIELD_LEN) != 0;
        let more_fragments = (data & HEADER_FIELD_MORE_FRAGMENTS) != 0;
        let start = (data & HEADER_FIELD_START) != 0;

        Header {
            length_included,
            more_fragments,
            start,
        }
    }
}
