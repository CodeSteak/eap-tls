use layers::{
    auth::{AnyMethod, AuthIdentityMethod, AuthMD5ChallengeMethod},
    eap_layer::EapOutput,
    AuthLayer, EapLayer,
};

mod layers;
mod message;

pub trait EapEnvironment {
    fn set_name(&mut self, name: &[u8]); // <- Extract Somehow

    fn name(&self) -> Option<&[u8]>; // <- Extract Somehow, make generic for Peer/Auth

    fn max_invalid_message_count(&self) -> u16 {
        10 // Some default value
    }

    fn max_retransmit_count(&self) -> u16 {
        4 // 3~5 Suggested by RFC
    }

    fn max_timeout_count(&self) -> u16 {
        10 // Some default value
    }
}

pub struct Authenticator {
    env: DefaultEnvironment,
    inner: EapLayer<AuthLayer<AnyMethod>>,
    buffer: Vec<u8>,
}

struct DefaultEnvironment {
    name: Option<Vec<u8>>,
}

impl DefaultEnvironment {
    fn new() -> Self {
        Self { name: None }
    }
}

impl EapEnvironment for DefaultEnvironment {
    fn set_name(&mut self, name: &[u8]) {
        self.name = Some(name.to_vec());
    }

    fn name(&self) -> Option<&[u8]> {
        self.name.as_deref()
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
                AuthIdentityMethod::new().into(),
                AuthMD5ChallengeMethod::new(password.as_bytes()).into(),
            ])),
            env: DefaultEnvironment::new(),
            buffer: Vec::new(),
        }
    }

    pub fn receive(&mut self, data: &[u8]) {
        self.buffer = data.to_vec();
    }

    pub fn step(&mut self) -> AuthenticatorStepResult {
        let Self {
            inner, //
            env,   //
            buffer,
        } = self;

        let res = if buffer.is_empty() {
            inner.start(env)
        } else {
            inner.receive(buffer, env)
        };

        AuthenticatorStepResult {
            status: match res.status {
                layers::eap_layer::EapStatus::Ok => AuthenticatorStepStatus::Ok,
                layers::eap_layer::EapStatus::Success => AuthenticatorStepStatus::Finished,
                layers::eap_layer::EapStatus::Failed(_) => AuthenticatorStepStatus::Error,
                layers::eap_layer::EapStatus::InternalError => AuthenticatorStepStatus::Error,
            },
            response: res.message.map(|m| m.to_bytes()),
        }
    }
}
