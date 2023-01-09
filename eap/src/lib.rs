use layers::{
    auth::{identity::IdentityMethod, md5_challange::MD5ChallengeMethod, AnyMethod},
    eap_layer::{InnerLayer as AuthInnerLayer, StateResult},
    AuthLayer, EapLayer,
};
use message::Message;

mod layers;
mod message;

trait EapEnvironment {
    fn set_name(&mut self, name: &[u8]); // <- Extract Somehow

    fn name(&self) -> Option<&[u8]>; // <- Extract Somehow, make generic for Peer/Auth

    fn send(&mut self, message: &[u8]);
}

pub struct Authenticator {
    inner: EapLayer<AuthLayer<AnyMethod>>,
    buffer: Vec<u8>,
}

struct AuthenticatorEnv {
    send_buffer: Option<Vec<u8>>,
}

impl EapEnvironment for AuthenticatorEnv {
    fn set_name(&mut self, name: &[u8]) {
        // TODO
    }

    fn name(&self) -> Option<&[u8]> {
        None
    }

    fn send(&mut self, message: &[u8]) {
        self.send_buffer = Some(message.to_vec());
    }
}

pub struct AuthenticatorStepResult {
    pub status: AuthenticatorStepStatus,
    pub response: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum AuthenticatorStepStatus {
    Ok,
    Error,
    Finished,
}

impl Authenticator {
    pub fn new(password: &str) -> Self {
        Self {
            inner: EapLayer::new(AuthLayer::new(vec![
                IdentityMethod::new().into(),
                MD5ChallengeMethod::new(password.as_bytes()).into(),
            ])),
            buffer: Vec::new(),
        }
    }

    pub fn receive(&mut self, data: &[u8]) {
        self.buffer = data.to_vec();
    }

    pub fn step(&mut self) -> AuthenticatorStepResult {
        let mut env = AuthenticatorEnv { send_buffer: None };
        let res = if self.buffer.is_empty() {
            self.inner.start(&mut env)
        } else {
            self.inner.receive(&self.buffer, &mut env)
        };

        match dbg!(res) {
            StateResult::Ok => AuthenticatorStepResult {
                status: AuthenticatorStepStatus::Ok,
                response: env.send_buffer,
            },
            StateResult::Finished => AuthenticatorStepResult {
                status: AuthenticatorStepStatus::Finished,
                response: env.send_buffer,
            },
            StateResult::Failed(_) => AuthenticatorStepResult {
                status: AuthenticatorStepStatus::Error,
                response: env.send_buffer,
            },
        }
    }
}
