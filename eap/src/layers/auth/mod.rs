mod auth_layer;
pub use auth_layer::AuthLayer;

pub mod identity;
pub mod md5_challange;

#[derive(Clone)]
pub enum AnyMethod {
    Identity(identity::IdentityMethod),
    MD5Challange(md5_challange::MD5ChallengeMethod),
}

impl auth_layer::InnerLayer for AnyMethod {
    fn method_identifier(&self) -> u8 {
        match self {
            AnyMethod::Identity(inner) => inner.method_identifier(),
            AnyMethod::MD5Challange(inner) => inner.method_identifier(),
        }
    }

    fn start(&mut self, env: &mut dyn crate::EapEnvironment) -> auth_layer::InnerResult {
        match self {
            AnyMethod::Identity(inner) => inner.start(env),
            AnyMethod::MD5Challange(inner) => inner.start(env),
        }
    }

    fn recv(
        &mut self,
        msg: &[u8],
        meta: &auth_layer::RecvMeta,
        env: &mut dyn crate::EapEnvironment,
    ) -> auth_layer::InnerResult {
        match self {
            AnyMethod::Identity(inner) => inner.recv(msg, meta, env),
            AnyMethod::MD5Challange(inner) => inner.recv(msg, meta, env),
        }
    }
}

impl Into<AnyMethod> for identity::IdentityMethod {
    fn into(self) -> AnyMethod {
        AnyMethod::Identity(self)
    }
}

impl Into<AnyMethod> for md5_challange::MD5ChallengeMethod {
    fn into(self) -> AnyMethod {
        AnyMethod::MD5Challange(self)
    }
}
