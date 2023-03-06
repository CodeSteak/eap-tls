mod peer_layer;
pub use peer_layer::PeerLayer;

mod identity;
pub use identity::PeerIdentityMethod;

mod md5_challenge;
pub use md5_challenge::PeerMD5ChallengeMethod;

#[cfg(feature = "tls")]
mod tls;

#[cfg(feature = "tls")]
pub use tls::PeerTlsMethod;

use self::peer_layer::PeerInnerLayer;

#[derive(Clone)]
pub enum AnyMethod {
    Identity(PeerIdentityMethod),
    MD5Challenge(PeerMD5ChallengeMethod),
    #[cfg(feature = "tls")]
    Tls(tls::PeerTlsMethod),
}

impl From<PeerIdentityMethod> for AnyMethod {
    fn from(method: PeerIdentityMethod) -> Self {
        Self::Identity(method)
    }
}

impl From<PeerMD5ChallengeMethod> for AnyMethod {
    fn from(method: PeerMD5ChallengeMethod) -> Self {
        Self::MD5Challenge(method)
    }
}

impl PeerInnerLayer for AnyMethod {
    fn method_identifier(&self) -> u8 {
        match self {
            Self::Identity(i) => i.method_identifier(),
            Self::MD5Challenge(i) => i.method_identifier(),
            #[cfg(feature = "tls")]
            Self::Tls(i) => i.method_identifier(),
        }
    }

    fn start(&mut self, env: &mut dyn crate::EapEnvironment) -> peer_layer::PeerInnerLayerResult {
        match self {
            Self::Identity(i) => i.start(env),
            Self::MD5Challenge(i) => i.start(env),
            #[cfg(feature = "tls")]
            Self::Tls(i) => i.start(env),
        }
    }

    fn recv(
        &mut self,
        msg: &[u8],
        meta: &peer_layer::RecvMeta,
        env: &mut dyn crate::EapEnvironment,
    ) -> peer_layer::PeerInnerLayerResult {
        match self {
            Self::Identity(i) => i.recv(msg, meta, env),
            Self::MD5Challenge(i) => i.recv(msg, meta, env),
            #[cfg(feature = "tls")]
            Self::Tls(i) => i.recv(msg, meta, env),
        }
    }
}
