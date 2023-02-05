use crate::{
    layers::{eap_layer::EapStatus, peer::AnyMethod, EapLayer, PeerLayer},
    DefaultEnvironment,
};

pub struct Peer {
    env: DefaultEnvironment,
    inner: EapLayer<PeerLayer<AnyMethod>>,
    buffer: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum PeerStepStatus {
    Ok,
    Error,
    Finished,
}

pub struct PeerStepResult {
    pub status: PeerStepStatus,
    pub response: Option<Vec<u8>>,
}

impl Peer {
    pub fn new(identity: &str, password: &str) -> Self {
        Self {
            inner: EapLayer::new(PeerLayer::new(vec![
                AnyMethod::Identity(crate::layers::peer::PeerIdentityMethod::new(
                    identity.as_bytes(),
                )),
                AnyMethod::MD5Challenge(crate::layers::peer::PeerMD5ChallengeMethod::new(
                    password.as_bytes(),
                )),
            ])),
            env: DefaultEnvironment::new(),
            buffer: Vec::new(),
        }
    }

    pub fn receive(&mut self, data: &[u8]) {
        self.buffer = data.to_vec();
    }

    pub fn step(&mut self) -> PeerStepResult {
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
                EapStatus::InternalError => PeerStepStatus::Error,
            },
            response: res.message.map(|m| m.to_bytes()),
        }
    }
}
