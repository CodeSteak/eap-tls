use crate::{layers::mux::HasId, util::OwnedSlice, EapEnvironment, EapEnvironmentResponse};

use super::super::peer_layer::{PeerMethodLayer, PeerMethodLayerResult, RecvMeta};

#[derive(Clone)]
pub struct PeerIdentityMethod {
    name: OwnedSlice<64>,
}

impl PeerIdentityMethod {
    #[allow(unused)]
    pub fn new(name: &[u8]) -> Self {
        Self { name: name.into() }
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

    fn recv<'a>(
        &mut self,
        msg: &[u8],
        _meta: &RecvMeta,
        env: &'a mut dyn EapEnvironment,
    ) -> PeerMethodLayerResult<'a> {
        if msg != b"" {
            return PeerMethodLayerResult::Failed(env);
        }

        PeerMethodLayerResult::Send(env.respond().write(self.name.as_ref()))
    }

    fn selectable_by_nak(&self) -> bool {
        false
    }
}

#[cfg(feature = "std")]
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

        assert!(matches!(
            method.recv(b"", &RecvMeta { message: m }, &mut env),
            PeerMethodLayerResult::Send(response) if response.slice() == b"bob",
        ));

        assert!(matches!(
            method.recv(b"invalid data", &RecvMeta { message: m }, &mut env),
            PeerMethodLayerResult::Failed(_),
        ));
    }
}
