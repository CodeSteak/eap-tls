use crate::layers::auth::auth_layer::{AuthMethodLayer, AuthMethodLayerResult};
use crate::layers::mux::TupleElement;
use crate::util::OwnedSlice;
use crate::{EapEnvironment, EapEnvironmentResponse};

use super::super::auth_layer::RecvMeta;

const METHOD_MD5_CHALLENGE: u8 = 4;

#[derive(Clone)]
pub struct AuthMD5ChallengeMethod {
    password: OwnedSlice<64>,
    value: OwnedSlice<64>, // <- Optional
    challange_data: [u8; 16],
}

impl TupleElement for AuthMD5ChallengeMethod {
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

impl AuthMD5ChallengeMethod {
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: password.try_into().expect("password too long for nostd"),
            value: OwnedSlice::new(),
            challange_data: [0; 16],
        }
    }

    #[cfg(test)]
    pub(crate) fn set_challange_data(&mut self, data: &[u8]) {
        self.challange_data.copy_from_slice(data);
    }
}

impl AuthMethodLayer for AuthMD5ChallengeMethod {
    fn method_identifier(&self) -> u8 {
        METHOD_MD5_CHALLENGE
    }

    fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> AuthMethodLayerResult<'a> {
        env.fill_random(&mut self.challange_data);

        let msg = env
            .respond()
            .write([self.challange_data.len() as u8].as_slice())
            .write(&self.challange_data);

        AuthMethodLayerResult::Send(msg)
    }

    fn recv<'a>(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        env: &'a mut dyn EapEnvironment,
    ) -> AuthMethodLayerResult<'a> {
        // WPA Supplicant sometimes a 17 as length (?), but the RFC says 16 bytes,
        // so we ignore the length field
        // See: https://www.rfc-editor.org/rfc/rfc1994#section-4.1
        // if msg.len() != 16 {
        //     return AuthInnerLayerResult::Failed;
        // }
        let mut md5_context = md5::Context::new();
        md5_context.consume([meta.message.identifier]);
        md5_context.consume(&self.password);
        md5_context.consume(self.challange_data);
        md5_context.consume(&self.value);
        let expected = md5_context.compute().0;

        if expected == msg[1..] {
            AuthMethodLayerResult::Finished(env)
        } else {
            AuthMethodLayerResult::Failed(env)
        }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use crate::{message::Message, DefaultEnvironment};

    use super::*;

    #[test]
    fn auth_md5_challenge_method() {
        let mut method = AuthMD5ChallengeMethod::new(b"42");
        assert_eq!(method.method_identifier(), METHOD_MD5_CHALLENGE);

        let mut env = DefaultEnvironment::new();

        let res = method.start(&mut env);
        assert!(matches!(res, AuthMethodLayerResult::Send(data) if data.slice().len() == 16+1));

        {
            // Wrong Response
            let mut method = method.clone();
            let m = Message::new(crate::message::MessageCode::Response, 0, b"bob");
            assert!(matches!(
                method.recv(
                    &[
                        0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                        0x12, 0x13, 0x14, 0x15, 0x16 // <- LOL Hex counting
                    ],
                    &RecvMeta { message: m },
                    &mut crate::DefaultEnvironment::new()
                ),
                AuthMethodLayerResult::Failed(_)
            ));
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
        assert!(matches!(
            method.recv(
                &crate::util::hex_to_vec("10 09 39 72 8a 8f 7f 82 f5 11 61 0c ff df 8b c3 1f"),
                &RecvMeta { message: m },
                &mut crate::DefaultEnvironment::new()
            ),
            AuthMethodLayerResult::Finished(_)
        ));
    }
}
