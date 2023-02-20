mod auth_layer;
pub use auth_layer::AuthLayer;

mod identity;
mod md5_challange;

#[cfg(feature = "tls")]
mod tls;

pub use identity::AuthIdentityMethod;
pub use md5_challange::AuthMD5ChallengeMethod;
#[cfg(feature = "tls")]
pub use tls::AuthTlsMethod;

#[allow(clippy::large_enum_variant)] // TODO:
#[derive(Clone)]
pub enum AnyMethod {
    Identity(identity::AuthIdentityMethod),
    MD5Challange(md5_challange::AuthMD5ChallengeMethod),
    #[cfg(feature = "tls")]
    Tls(AuthTlsMethod),
}

impl auth_layer::AuthInnerLayer for AnyMethod {
    fn method_identifier(&self) -> u8 {
        match self {
            AnyMethod::Identity(inner) => inner.method_identifier(),
            AnyMethod::MD5Challange(inner) => inner.method_identifier(),
            #[cfg(feature = "tls")]
            AnyMethod::Tls(inner) => inner.method_identifier(),
        }
    }

    fn start(&mut self, env: &mut dyn crate::EapEnvironment) -> auth_layer::AuthInnerLayerResult {
        match self {
            AnyMethod::Identity(inner) => inner.start(env),
            AnyMethod::MD5Challange(inner) => inner.start(env),
            #[cfg(feature = "tls")]
            AnyMethod::Tls(inner) => inner.start(env),
        }
    }

    fn recv(
        &mut self,
        msg: &[u8],
        meta: &auth_layer::RecvMeta,
        env: &mut dyn crate::EapEnvironment,
    ) -> auth_layer::AuthInnerLayerResult {
        match self {
            AnyMethod::Identity(inner) => inner.recv(msg, meta, env),
            AnyMethod::MD5Challange(inner) => inner.recv(msg, meta, env),
            #[cfg(feature = "tls")]
            AnyMethod::Tls(inner) => inner.recv(msg, meta, env),
        }
    }
}

#[allow(unused)]
impl From<identity::AuthIdentityMethod> for AnyMethod {
    fn from(val: identity::AuthIdentityMethod) -> Self {
        AnyMethod::Identity(val)
    }
}

#[allow(unused)]
impl From<md5_challange::AuthMD5ChallengeMethod> for AnyMethod {
    fn from(val: md5_challange::AuthMD5ChallengeMethod) -> Self {
        AnyMethod::MD5Challange(val)
    }
}

#[cfg(feature = "tls")]
#[allow(unused)]
impl From<AuthTlsMethod> for AnyMethod {
    fn from(val: AuthTlsMethod) -> Self {
        AnyMethod::Tls(val)
    }
}
