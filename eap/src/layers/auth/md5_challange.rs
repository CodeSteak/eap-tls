use crate::layers::auth::auth_layer::{AuthInnerLayer, AuthInnerLayerResult};
use crate::layers::mux::HasId;
use crate::message::MessageContent;
use crate::EapEnvironment;

use super::auth_layer::RecvMeta;

const METHOD_MD5_CHALLENGE: u8 = 4;

#[derive(Clone)]
pub struct AuthMD5ChallengeMethod {
    password: Vec<u8>,
    value: Vec<u8>, // <- Optional
    challange_data: [u8; 16],
}

impl HasId for AuthMD5ChallengeMethod {
    type Target = dyn AuthInnerLayer;

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

impl AuthMD5ChallengeMethod {
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
            value: vec![],
            challange_data: [0; 16],
        }
    }

    #[cfg(test)]
    pub(crate) fn set_challange_data(&mut self, data: &[u8]) {
        self.challange_data.copy_from_slice(data);
    }
}

impl AuthInnerLayer for AuthMD5ChallengeMethod {
    fn method_identifier(&self) -> u8 {
        METHOD_MD5_CHALLENGE
    }

    fn start(&mut self, _env: &mut dyn EapEnvironment) -> AuthInnerLayerResult {
        getrandom::getrandom(&mut self.challange_data).unwrap();

        let mut data = vec![self.challange_data.len() as u8]; // Fixed length field
        data.extend_from_slice(&self.challange_data);

        AuthInnerLayerResult::Send(MessageContent { data })
    }

    fn recv(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        _env: &mut dyn EapEnvironment,
    ) -> AuthInnerLayerResult {
        // WPA Supplicant sometimes a 17 as length (?), but the RFC says 16 bytes,
        // so we ignore the length field
        // See: https://www.rfc-editor.org/rfc/rfc1994#section-4.1
        // if msg.len() != 16 {
        //     return AuthInnerLayerResult::Failed;
        // }

        let mut hashed_data = Vec::new();
        hashed_data.extend_from_slice(&[meta.message.identifier]);
        hashed_data.extend_from_slice(&self.password);
        hashed_data.extend_from_slice(&self.challange_data);
        hashed_data.extend_from_slice(&self.value);

        let expected = md5::compute(hashed_data).0;

        if expected == msg[1..] {
            AuthInnerLayerResult::Finished
        } else {
            AuthInnerLayerResult::Failed
        }
    }
}

#[cfg(test)]
mod test {
    use crate::message::Message;

    use super::*;

    #[test]
    fn auth_md5_challenge_method() {
        let mut method = AuthMD5ChallengeMethod::new(b"42");
        assert_eq!(method.method_identifier(), METHOD_MD5_CHALLENGE);

        let res = method.start(&mut crate::DefaultEnvironment::new());
        assert!(
            matches!(res, AuthInnerLayerResult::Send(MessageContent { data }) if data.len() == 16+1)
        );

        {
            // Wrong Response
            let mut method = method.clone();
            let m = Message::new(crate::message::MessageCode::Response, 0, b"bob");
            assert_eq!(
                method.recv(
                    &[
                        0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                        0x12, 0x13, 0x14, 0x15, 0x16
                    ],
                    &RecvMeta {
                        // <- LOL Hex counting
                        message: &m,
                    },
                    &mut crate::DefaultEnvironment::new()
                ),
                AuthInnerLayerResult::Failed
            );
        }

        // Generated via wpa supplicant
        method.set_challange_data(&crate::util::hex_to_vec(
            "c7 24 0a c7 c5 94 58 ee 8f 7a 98 35 6c 61 53 f0",
        ));

        let m = Message::new(
            crate::message::MessageCode::Response,
            0x69, /* <- part of hash */
            b"",
        );
        assert_eq!(
            method.recv(
                &crate::util::hex_to_vec("10 09 39 72 8a 8f 7f 82 f5 11 61 0c ff df 8b c3 1f"),
                &RecvMeta { message: &m },
                &mut crate::DefaultEnvironment::new()
            ),
            AuthInnerLayerResult::Finished
        );
    }
}
