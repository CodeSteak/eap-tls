use crate::eap_tls::{CommonTLS, EapCommonResult};
use std::sync::Arc;

use rustls::{
    server::AllowAnyAuthenticatedClient, Certificate, PrivateKey, ServerConfig, ServerConnection,
};

use crate::{message::MessageContent, EapEnvironment};

use super::auth_layer::{
    AuthInnerLayer as ThisLayer, AuthInnerLayerResult as ThisLayerResult, RecvMeta,
};

const METHOD_TLS: u8 = 13;

pub struct AuthTlsMethod {
    inner: Option<CommonTLS<ServerConnection>>,
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
        Self { inner: None }
    }

    fn create_common_tls() -> CommonTLS<ServerConnection> {
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

        CommonTLS::new(ServerConnection::new(Arc::new(config)).unwrap())
    }
}

impl ThisLayer for AuthTlsMethod {
    fn method_identifier(&self) -> u8 {
        METHOD_TLS
    }

    fn start(&mut self, _env: &mut dyn EapEnvironment) -> ThisLayerResult {
        let inner = self
            .inner
            .get_or_insert_with(AuthTlsMethod::create_common_tls);

        ThisLayerResult::Send(MessageContent {
            data: inner.start_packet(),
        })
    }

    fn recv(
        &mut self,
        msg: &[u8],
        _meta: &RecvMeta,
        _env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        let inner = self
            .inner
            .get_or_insert_with(AuthTlsMethod::create_common_tls);

        match inner.process(msg, true) {
            Ok(EapCommonResult::Finished) => ThisLayerResult::Finished,
            Ok(EapCommonResult::Next(data)) => ThisLayerResult::Send(MessageContent { data }),
            Err(()) => ThisLayerResult::Failed,
        }
    }

    fn selectable_by_nak(&self) -> bool {
        false
    }
}
