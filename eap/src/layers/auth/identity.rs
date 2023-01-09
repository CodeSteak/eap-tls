use crate::{message::MessageContent, EapEnvironment};

use super::auth_layer::{InnerLayer as ThisLayer, InnerResult as ThisLayerResult, RecvMeta};

const METHOD_IDENTITY: u8 = 1;

#[derive(Clone)]
pub struct IdentityMethod;

impl IdentityMethod {
    pub fn new() -> Self {
        Self
    }
}

impl ThisLayer for IdentityMethod {
    fn method_identifier(&self) -> u8 {
        METHOD_IDENTITY
    }

    fn start(&mut self, env: &mut dyn EapEnvironment) -> ThisLayerResult {
        ThisLayerResult::Send(MessageContent { data: vec![] })
    }

    fn recv(
        &mut self,
        msg: &[u8],
        _meta: &RecvMeta,
        env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        env.set_name(msg);
        ThisLayerResult::NextLayer
    }
}
