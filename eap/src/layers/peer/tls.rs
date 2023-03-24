use std::sync::Arc;

use dummycert::TlsConfig;
use rustls::{Certificate, ClientConfig, ClientConnection, PrivateKey};

use crate::{
    eap_tls::{CommonTLS, EapCommonResult},
    layers::mux::HasId,
    message::MessageContent,
};

use super::peer_layer::{PeerMethodLayer, PeerMethodLayerResult, RecvMeta};

pub struct PeerTlsMethod {
    config: TlsConfig,
    inner: Option<CommonTLS<ClientConnection>>,
}

impl HasId for PeerTlsMethod {
    type Target = dyn PeerMethodLayer;
    fn id(&self) -> u8 {
        self.method_identifier()
    }

    fn get(&self) -> &Self::Target {
        self
    }

    fn get_mut(&mut self) -> &mut Self::Target {
        self
    }
}

const METHOD_TLS: u8 = 13;

impl PeerTlsMethod {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            inner: None,
        }
    }

    fn create_common_tls(config: &TlsConfig) -> CommonTLS<ClientConnection> {
        let server_cert = rustls_pemfile::read_all(&mut config.server_cert.as_ref())
            .unwrap()
            .into_iter()
            .flat_map(|cert| match cert {
                rustls_pemfile::Item::X509Certificate(cert) => Some(Certificate(cert)),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert!(!server_cert.is_empty());

        let server_key = rustls_pemfile::read_one(&mut config.server_key.as_ref())
            .unwrap()
            .and_then(|cert| match cert {
                rustls_pemfile::Item::PKCS8Key(key) => Some(PrivateKey(key)),
                _ => None,
            })
            .unwrap();

        let ca_cert = rustls_pemfile::read_all(&mut config.ca_cert.as_ref())
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

        let mut config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_ca_store)
            .with_single_cert(server_cert, server_key)
            .expect("bad certificate/key");

        config.enable_sni = false;

        let server_name = rustls::ServerName::try_from("dummy.example.com").unwrap();
        CommonTLS::new(ClientConnection::new(Arc::new(config), server_name).unwrap())
    }
}

impl Clone for PeerTlsMethod {
    fn clone(&self) -> Self {
        PeerTlsMethod::new(self.config.clone())
    }
}

impl PeerMethodLayer for PeerTlsMethod {
    fn method_identifier(&self) -> u8 {
        METHOD_TLS
    }

    fn recv(
        &mut self,
        msg: &[u8],
        _meta: &RecvMeta,
        _env: &mut dyn crate::EapEnvironment,
    ) -> PeerMethodLayerResult {
        let inner = self
            .inner
            .get_or_insert_with(|| PeerTlsMethod::create_common_tls(&self.config));

        match inner.process(msg, false) {
            Ok(EapCommonResult::Finished) => {
                unreachable!();
            }
            Ok(EapCommonResult::Next(data)) => {
                PeerMethodLayerResult::Send(MessageContent::new(&data))
            }
            Err(()) => PeerMethodLayerResult::Failed,
        }
    }

    fn can_succeed(&self) -> Option<bool> {
        match &self.inner {
            Some(inner) => Some(inner.finished),
            None => Some(false),
        }
    }
}
