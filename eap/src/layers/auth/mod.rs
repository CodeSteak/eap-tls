mod auth_layer;
pub use auth_layer::AuthLayer;

mod identity;
mod md5_challange;

pub use identity::AuthIdentityMethod;
pub use md5_challange::AuthMD5ChallengeMethod;

#[derive(Clone)]
pub enum AnyMethod {
    Identity(identity::AuthIdentityMethod),
    MD5Challange(md5_challange::AuthMD5ChallengeMethod),
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

impl Into<AnyMethod> for identity::AuthIdentityMethod {
    fn into(self) -> AnyMethod {
        AnyMethod::Identity(self)
    }
}

impl Into<AnyMethod> for md5_challange::AuthMD5ChallengeMethod {
    fn into(self) -> AnyMethod {
        AnyMethod::MD5Challange(self)
    }
}
