use crate::{layers::mux::HasId, message::MessageContent, EapEnvironment};

use super::auth_layer::{
    AuthInnerLayer as ThisLayer, AuthInnerLayerResult as ThisLayerResult, RecvMeta,
};

const METHOD_IDENTITY: u8 = 1;

#[derive(Clone, Default)]
pub struct AuthIdentityMethod;

impl AuthIdentityMethod {
    pub fn new() -> Self {
        Self
    }
}

impl HasId for AuthIdentityMethod {
    type Target = dyn ThisLayer;

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

impl ThisLayer for AuthIdentityMethod {
    fn method_identifier(&self) -> u8 {
        METHOD_IDENTITY
    }

    fn start(&mut self, _env: &mut dyn EapEnvironment) -> ThisLayerResult {
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

    fn selectable_by_nak(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::message::Message;

    use super::*;

    #[test]
    fn auth_identity_method() {
        let mut env = crate::DefaultEnvironment::new();
        let mut method = AuthIdentityMethod::new();
        assert_eq!(method.method_identifier(), METHOD_IDENTITY);
        assert_eq!(
            method.start(&mut env),
            ThisLayerResult::Send(MessageContent { data: vec![] })
        );

        let m = Message::new(crate::message::MessageCode::Response, 0, b"bob");
        assert_eq!(
            method.recv(b"bob", &RecvMeta { message: &m }, &mut env),
            ThisLayerResult::NextLayer
        );

        assert_eq!(env.name(), Some(&b"bob"[..]));
    }
}
