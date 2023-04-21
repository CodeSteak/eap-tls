use crate::{layers::mux::TupleElement, EapEnvironment, EapEnvironmentResponse};

use super::super::auth_layer::{
    AuthMethodLayer as ThisLayer, AuthMethodLayerResult as ThisLayerResult, RecvMeta,
};

const METHOD_IDENTITY: u8 = 1;

#[derive(Clone, Default)]
pub struct AuthIdentityMethod;

impl AuthIdentityMethod {
    pub fn new() -> Self {
        Self
    }
}

impl TupleElement for AuthIdentityMethod {
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

    fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> ThisLayerResult<'a> {
        ThisLayerResult::Send(env.respond().write(&[]))
    }

    fn recv<'a>(
        &mut self,
        msg: &[u8],
        _meta: &RecvMeta,
        env: &'a mut dyn EapEnvironment,
    ) -> ThisLayerResult<'a> {
        env.set_name(msg);
        ThisLayerResult::NextLayer(env)
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
    fn auth_identity_method() {
        let mut env = crate::DefaultEnvironment::new();
        let mut method = AuthIdentityMethod::new();
        assert_eq!(method.method_identifier(), METHOD_IDENTITY);

        assert!(matches!(
            method.start(&mut env),
            ThisLayerResult::Send(content) if content.slice().is_empty()
        ));

        let m = Message::new(crate::message::MessageCode::Response, 0, b"bob");
        assert!(matches!(
            method.recv(b"bob", &RecvMeta { message: m }, &mut env),
            ThisLayerResult::NextLayer(_)
        ));

        assert_eq!(env.name(), Some(&b"bob"[..]));
    }
}
