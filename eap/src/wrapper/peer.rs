#[cfg(feature = "tls")]
use dummycert::TlsConfig;

use crate::{
    layers::{
        eap_layer::EapStatus,
        mux::TupleById,
        peer::{peer_layer::PeerMethodLayer, PeerIdentityMethod, PeerMD5ChallengeMethod},
        EapLayer, PeerLayer,
    },
    DefaultEnvironment,
};

pub struct Peer<I> {
    env: DefaultEnvironment,
    inner: EapLayer<PeerLayer<I>>,
    buffer: Vec<u8>,
}

pub use common::EapStepResult as PeerStepResult;
pub use common::EapStepStatus as PeerStepStatus;
pub use common::EapWrapper;

pub type MD5Peer = Peer<(PeerIdentityMethod, PeerMD5ChallengeMethod)>;
impl Peer<(PeerIdentityMethod, PeerMD5ChallengeMethod)> {
    pub fn new_password(identity: &str, password: &str) -> Self {
        Self {
            inner: EapLayer::new(
                PeerLayer::new()
                    .with(crate::layers::peer::PeerIdentityMethod::new(
                        identity.as_bytes(),
                    ))
                    .with(crate::layers::peer::PeerMD5ChallengeMethod::new(
                        password.as_bytes(),
                    )),
            ),
            env: DefaultEnvironment::new(),
            buffer: Vec::new(),
        }
    }
}

#[cfg(feature = "tls")]
pub type TlsPeer = Peer<(PeerIdentityMethod, crate::eap_rustls::PeerTlsMethod)>;


#[cfg(feature = "tls")]
impl Peer<(PeerIdentityMethod, crate::eap_rustls::PeerTlsMethod)> {
    pub fn new_tls(identity: &str, config: TlsConfig) -> Self {
        Self {
            inner: EapLayer::new(
                PeerLayer::new()
                    .with(crate::layers::peer::PeerIdentityMethod::new(
                        identity.as_bytes(),
                    ))
                    .with(crate::eap_rustls::PeerTlsMethod::new(config)),
            ),
            env: DefaultEnvironment::new(),
            buffer: Vec::new(),
        }
    }
}

impl<I> EapWrapper for Peer<I>
where
    I: TupleById<dyn PeerMethodLayer>,
{
    fn receive(&mut self, data: &[u8]) {
        self.buffer = data.to_vec();
    }

    fn step(&mut self) -> PeerStepResult<'_> {
        let Self {
            inner, //
            env,   //
            buffer,
        } = self;

        let res = if buffer.is_empty() {
            if inner.has_started() {
                inner.timeout(env)
            } else {
                inner.start(env)
            }
        } else {
            inner.receive(
                &{
                    let buf = buffer.clone();
                    buffer.clear();
                    buf
                },
                env,
            )
        };

        PeerStepResult {
            status: match res.status {
                EapStatus::Ok => PeerStepStatus::Ok,
                EapStatus::Success => PeerStepStatus::Finished,
                EapStatus::Failed(_) => PeerStepStatus::Error,
                EapStatus::InternalError(_) => PeerStepStatus::Error,
            },
            response: res.message.map(|m| m.into_slice()),
        }
    }
}
