use crate::EapEnvironment;

use super::peer_layer::{PeerInnerLayer, PeerInnerLayerResult, RecvMeta};

#[derive(Clone)]
pub struct PeerMD5ChallengeMethod {
    password: Vec<u8>,
}

impl PeerMD5ChallengeMethod {
    #[allow(unused)]
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
        }
    }
}

impl PeerInnerLayer for PeerMD5ChallengeMethod {
    fn method_identifier(&self) -> u8 {
        4
    }

    fn start(&mut self, _env: &mut dyn EapEnvironment) -> PeerInnerLayerResult {
        PeerInnerLayerResult::Noop
    }

    fn recv(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        _env: &mut dyn crate::EapEnvironment,
    ) -> PeerInnerLayerResult {
        // first byte is length of the challenge part,
        // but the content is vague and does not matter
        if msg.len() != 17 {
            return PeerInnerLayerResult::Failed;
        }

        let mut hashed_data = Vec::new();
        hashed_data.extend_from_slice(&[meta.message.identifier]);
        hashed_data.extend_from_slice(&self.password);
        hashed_data.extend_from_slice(&msg[1..]);

        let hash = md5::compute(hashed_data).0;

        let mut response = vec![0u8; 17];
        response[0] = hash.len() as u8; // fixed length
        response[1..].copy_from_slice(&hash);

        PeerInnerLayerResult::Send(crate::message::MessageContent { data: response })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_against_auth() {
        let password = b"42".to_vec();
        let mut env = crate::DefaultEnvironment::new();
        let mut method = PeerMD5ChallengeMethod::new(&password);

        assert_eq!(method.method_identifier(), 4);
        assert_eq!(method.start(&mut env), PeerInnerLayerResult::Noop);

        let m = crate::message::Message::new(
            crate::message::MessageCode::Response,
            0x69,
            &crate::util::hex_to_vec("10 c7 24 0a c7 c5 94 58 ee 8f 7a 98 35 6c 61 53 f0"),
        );

        let result = method.recv(&m.data, &RecvMeta { message: &m }, &mut env);

        assert_eq!(
            result,
            PeerInnerLayerResult::Send(crate::message::MessageContent {
                data: crate::util::hex_to_vec("10 09 39 72 8a 8f 7f 82 f5 11 61 0c ff df 8b c3 1f"),
            })
        );
    }

    #[test]
    fn test_invalid_challenge() {
        let password = b"42".to_vec();
        let mut env = crate::DefaultEnvironment::new();
        let mut method = PeerMD5ChallengeMethod::new(&password);

        let m = crate::message::Message::new(
            crate::message::MessageCode::Response,
            0x69,
            &crate::util::hex_to_vec("10 c7 24 0a c7"),
        );

        let result = method.recv(&m.data, &RecvMeta { message: &m }, &mut env);
        assert_eq!(result, PeerInnerLayerResult::Failed);
    }
}
