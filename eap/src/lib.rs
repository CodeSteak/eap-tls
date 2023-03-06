mod wrapper;
pub use wrapper::*;
#[cfg(feature = "tls")]
mod eap_tls;
mod layers;
mod message;
pub mod util;

pub trait EapEnvironment {
    fn set_name(&mut self, name: &[u8]); // <- Extract Somehow

    fn name(&self) -> Option<&[u8]>; // <- Extract Somehow, make generic for Peer/Auth

    fn max_invalid_message_count(&self) -> u16 {
        10 // Some default value
    }

    fn max_retransmit_count(&self) -> u16 {
        4 // 3~5 Suggested by RFC
    }

    fn max_timeout_count(&self) -> u16 {
        10 // Some default value
    }
}

struct DefaultEnvironment {
    name: Option<Vec<u8>>,
}

impl DefaultEnvironment {
    fn new() -> Self {
        Self { name: None }
    }
}

impl EapEnvironment for DefaultEnvironment {
    fn set_name(&mut self, name: &[u8]) {
        self.name = Some(name.to_vec());
    }

    fn name(&self) -> Option<&[u8]> {
        self.name.as_deref()
    }
}
