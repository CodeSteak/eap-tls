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
        include_bytes!("certs/dh.pem").to_vec()
    }

    pub fn dummy_server() -> Self {
        Self {
            ca_cert: include_bytes!("certs/ca.crt").to_vec(),
            server_cert: include_bytes!("certs/server-cert.crt").to_vec(),
            server_key: include_bytes!("certs/server-key.pem").to_vec(),
            dh_params: Self::default_dh_params(),
        }
    }

    pub fn dummy_client() -> Self {
        Self {
            ca_cert: include_bytes!("certs/ca.crt").to_vec(),
            server_cert: include_bytes!("certs/client-cert.crt").to_vec(),
            server_key: include_bytes!("certs/client-key.pem").to_vec(),
            dh_params: Self::default_dh_params(),
        }
    }
}
