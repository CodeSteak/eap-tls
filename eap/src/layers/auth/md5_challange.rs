use rand::RngCore;

use crate::layers::auth::auth_layer::{InnerLayer as ThisLayer, InnerResult as ThisLayerResult};
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

impl AuthMD5ChallengeMethod {
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
            value: vec![],
            challange_data: [0; 16],
        }
    }
}

impl ThisLayer for AuthMD5ChallengeMethod {
    fn method_identifier(&self) -> u8 {
        METHOD_MD5_CHALLENGE
    }

    fn start(&mut self, _env: &mut dyn EapEnvironment) -> ThisLayerResult {
        rand::thread_rng().fill_bytes(&mut self.challange_data);

        let mut data = vec![self.challange_data.len() as u8];
        data.extend_from_slice(&self.challange_data);

        ThisLayerResult::Send(MessageContent { data })
    }

    fn recv(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        _env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        let mut hashed_data = Vec::new();
        hashed_data.extend_from_slice(&[meta.message.identifier]);
        hashed_data.extend_from_slice(&self.password);
        hashed_data.extend_from_slice(&self.challange_data);
        hashed_data.extend_from_slice(&self.value);

        let expected = md5::compute(hashed_data).0;

        if expected == msg[1..] {
            ThisLayerResult::Finished
        } else {
            ThisLayerResult::Failed
        }
    }
}
