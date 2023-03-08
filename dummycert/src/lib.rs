#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TlsConfig {
    pub ca_cert: Vec<u8>,
    pub server_cert: Vec<u8>,
    pub server_key: Vec<u8>,
    pub dh_params: Vec<u8>,
}

impl TlsConfig {
    pub fn new(
        ca_cert: Vec<u8>,
        server_cert: Vec<u8>,
        server_key: Vec<u8>,
        dh_params: Option<Vec<u8>>,
    ) -> Self {
        Self {
            ca_cert,
            server_cert,
            server_key,
            dh_params: dh_params.unwrap_or_else(Self::default_dh_params),
        }
    }

    fn default_dh_params() -> Vec<u8> {
        include_bytes!("rsa/dh.pem").to_vec()
    }

    pub fn dummy_server() -> Self {
        Self::dummy_server_ed25519()
    }

    pub fn dummy_client() -> Self {
        Self::dummy_client_ed25519()
    }

    pub fn dummy_server_ed25519() -> Self {
        Self {
            ca_cert: include_bytes!("ed25519/ca.crt").to_vec(),
            server_cert: include_bytes!("ed25519/server-cert.crt").to_vec(),
            server_key: include_bytes!("ed25519/server-key.pem").to_vec(),
            dh_params: Self::default_dh_params(),
        }
    }

    pub fn dummy_client_ed25519() -> Self {
        Self {
            ca_cert: include_bytes!("ed25519/ca.crt").to_vec(),
            server_cert: include_bytes!("ed25519/client-cert.crt").to_vec(),
            server_key: include_bytes!("ed25519/client-key.pem").to_vec(),
            dh_params: Self::default_dh_params(),
        }
    }

    pub fn dummy_server_rsa() -> Self {
        Self {
            ca_cert: include_bytes!("rsa/ca.crt").to_vec(),
            server_cert: include_bytes!("rsa/server-cert.crt").to_vec(),
            server_key: include_bytes!("rsa/server-key.pem").to_vec(),
            dh_params: Self::default_dh_params(),
        }
    }

    pub fn dummy_client_rsa() -> Self {
        Self {
            ca_cert: include_bytes!("rsa/ca.crt").to_vec(),
            server_cert: include_bytes!("rsa/client-cert.crt").to_vec(),
            server_key: include_bytes!("rsa/client-key.pem").to_vec(),
            dh_params: Self::default_dh_params(),
        }
    }
}
