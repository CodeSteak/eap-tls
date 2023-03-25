use crate::{
    eap_rustls::{CommonTLS, EapCommonResult},
    layers::mux::HasId,
    EapEnvironmentResponse,
};
use std::sync::Arc;

use dummycert::TlsConfig;
use rustls::{
    server::AllowAnyAuthenticatedClient, Certificate, PrivateKey, ServerConfig, ServerConnection,
};

use crate::EapEnvironment;

use crate::layers::auth::auth_layer::{AuthMethodLayer, AuthMethodLayerResult, RecvMeta};

const METHOD_TLS: u8 = 13;

pub struct AuthTlsMethod {
    config: TlsConfig,
    inner: Option<CommonTLS<ServerConnection>>,
}

impl HasId for AuthTlsMethod {
    type Target = dyn AuthMethodLayer;

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

impl Clone for AuthTlsMethod {
    fn clone(&self) -> Self {
        AuthTlsMethod::new(self.config.clone())
    }
}

impl AuthTlsMethod {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            inner: None,
        }
    }

    fn create_common_tls(server_config: &TlsConfig) -> CommonTLS<ServerConnection> {
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

impl AuthMethodLayer for AuthTlsMethod {
    fn method_identifier(&self) -> u8 {
        METHOD_TLS
    }

    fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> AuthMethodLayerResult<'a> {
        let inner = self
            .inner
            .get_or_insert_with(|| AuthTlsMethod::create_common_tls(&self.config));

        AuthMethodLayerResult::Send(env.respond().write(inner.start_packet()))
    }

    fn recv<'a>(
        &mut self,
        msg: &[u8],
        _meta: &RecvMeta,
        env: &'a mut dyn EapEnvironment,
    ) -> AuthMethodLayerResult<'a> {
        let inner = self
            .inner
            .get_or_insert_with(|| AuthTlsMethod::create_common_tls(&self.config));

        match inner.process(msg, true) {
            Ok(EapCommonResult::Finished) => AuthMethodLayerResult::Finished(env),
            Ok(EapCommonResult::Next(data)) => {
                AuthMethodLayerResult::Send(env.respond().write(&data))
            }
            Err(()) => AuthMethodLayerResult::Failed(env),
        }
    }

    fn selectable_by_nak(&self) -> bool {
        false
    }
}
