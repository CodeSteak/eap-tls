use crate::{layers::mux::HasId, util::OwnedSlice, EapEnvironmentResponse};

use super::super::peer_layer::{PeerMethodLayer, PeerMethodLayerResult, RecvMeta};

#[derive(Clone)]
pub struct PeerMD5ChallengeMethod {
    password: OwnedSlice<64>,
}

impl PeerMD5ChallengeMethod {
    #[allow(unused)]
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: password.try_into().expect("password too long for nostd"),
        }
    }
}

impl HasId for PeerMD5ChallengeMethod {
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

impl PeerMethodLayer for PeerMD5ChallengeMethod {
    fn method_identifier(&self) -> u8 {
        4
    }

    fn can_succeed(&self) -> Option<bool> {
        Some(true)
    }

    fn recv<'a>(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        env: &'a mut dyn crate::EapEnvironment,
    ) -> PeerMethodLayerResult<'a> {
        // first byte is length of the challenge part,
        // but the content is vague and does not matter
        if msg.len() != 17 {
            return PeerMethodLayerResult::Failed(env);
        }

        let mut md5_context = md5::Context::new();
        md5_context.consume([meta.message.identifier]);
        md5_context.consume(&self.password);
        md5_context.consume(&msg[1..]);

        let hash = md5_context.compute().0;

        PeerMethodLayerResult::Send(
            env.respond() //
                .write(&[hash.len() as u8])
                .write(&hash),
        )
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_against_auth() {
        let password = b"42".to_vec();
        let mut env = crate::DefaultEnvironment::new();
        let mut method = PeerMD5ChallengeMethod::new(&password);

        assert_eq!(method.method_identifier(), 4);

        let data = crate::util::hex_to_vec("10 c7 24 0a c7 c5 94 58 ee 8f 7a 98 35 6c 61 53 f0");
        let m = crate::message::Message::new(crate::message::MessageCode::Response, 0x69, &data);

        let result = method.recv(m.body, &RecvMeta { message: m }, &mut env);

        let expected =
            crate::util::hex_to_vec("10 09 39 72 8a 8f 7f 82 f5 11 61 0c ff df 8b c3 1f");

        assert!(
            matches!(result, PeerMethodLayerResult::Send(content) if content.slice() == expected)
        );
    }

    #[test]
    fn test_invalid_challenge() {
        let password = b"42".to_vec();
        let mut env = crate::DefaultEnvironment::new();
        let mut method = PeerMD5ChallengeMethod::new(&password);

        let data = crate::util::hex_to_vec("10 c7 24 0a c7");
        let m = crate::message::Message::new(crate::message::MessageCode::Response, 0x69, &data);

        let result = method.recv(m.body, &RecvMeta { message: m }, &mut env);

        assert!(matches!(result, PeerMethodLayerResult::Failed(_)));
    }
}
