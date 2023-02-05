#[allow(
    non_camel_case_types,
    non_upper_case_globals,
    improper_ctypes,
    non_snake_case,
    clippy::all
)] // improper_ctypes for u128 values
pub(crate) mod bindings_peer;

#[allow(
    non_camel_case_types,
    non_upper_case_globals,
    improper_ctypes,
    non_snake_case,
    clippy::all
)] // improper_ctypes for u128 values
pub(crate) mod bindings_server;

pub mod peer;
pub mod server;
pub mod util;
//
#[cfg(test)]
mod test;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EapStatus {
    Ok,
    Finished,
    Failed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EapMethod {
    TLS,
    MD5,
}

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
        include_bytes!("dummy/dh.pem").to_vec()
    }

    pub fn dummy_server() -> Self {
        Self {
            ca_cert: include_bytes!("dummy/ca.der").to_vec(),
            server_cert: include_bytes!("dummy/server-cert.der").to_vec(),
            server_key: include_bytes!("dummy/server-key.der").to_vec(),
            dh_params: Self::default_dh_params(),
        }
    }

    pub fn dummy_client() -> Self {
        Self {
            ca_cert: include_bytes!("dummy/ca.der").to_vec(),
            server_cert: include_bytes!("dummy/client-cert.der").to_vec(),
            server_key: include_bytes!("dummy/client-key.der").to_vec(),
            dh_params: Self::default_dh_params(),
        }
    }
}
