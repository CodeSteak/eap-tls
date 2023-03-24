use crate::{layers::mux::HasId, message::MessageContent, EapEnvironment};

use super::peer_layer::{PeerMethodLayer, PeerMethodLayerResult, RecvMeta};

#[derive(Clone)]
pub struct PeerIdentityMethod {
    name: Vec<u8>,
}

impl PeerIdentityMethod {
    #[allow(unused)]
    pub fn new(name: &[u8]) -> Self {
        Self {
            name: name.to_vec(),
        }
    }
}

impl HasId for PeerIdentityMethod {
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

impl PeerMethodLayer for PeerIdentityMethod {
    fn method_identifier(&self) -> u8 {
        1
    }

    fn recv(
        &mut self,
        msg: &[u8],
        _meta: &RecvMeta,
        _env: &mut dyn EapEnvironment,
    ) -> PeerMethodLayerResult {
        if msg != b"" {
            return PeerMethodLayerResult::Failed;
        }

        PeerMethodLayerResult::Send(MessageContent {
            data: self.name.clone(),
        })
    }

    fn selectable_by_nak(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::message::Message;

    use super::*;

    #[test]
    fn peer_identity_method() {
        let mut env = crate::DefaultEnvironment::new();
        let mut method = PeerIdentityMethod::new(b"bob");
        assert_eq!(method.method_identifier(), 1);

        let m = Message::new(crate::message::MessageCode::Response, 0, b"");

        assert_eq!(
            method.recv(b"", &RecvMeta { message: &m }, &mut env),
            PeerMethodLayerResult::Send(MessageContent {
                data: b"bob".to_vec()
            })
        );

        assert_eq!(
            method.recv(b"invalid data", &RecvMeta { message: &m }, &mut env),
            PeerMethodLayerResult::Failed
        );
    }
}
