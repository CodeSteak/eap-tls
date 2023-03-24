use crate::{
    layers::{
        self,
        auth::{AuthIdentityMethod, AuthInnerLayer, AuthMD5ChallengeMethod},
        mux::TupleById,
        AuthLayer, EapLayer,
    },
    DefaultEnvironment,
};

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

pub struct Authenticator<I> {
    env: DefaultEnvironment,
    inner: EapLayer<AuthLayer<I>>,
    buffer: Vec<u8>,
}

impl Authenticator<(AuthIdentityMethod, AuthMD5ChallengeMethod)> {
    pub fn new(password: &str) -> Self {
        Self {
            inner: EapLayer::new(
                AuthLayer::new()
                    .with(AuthIdentityMethod::new())
                    .with(AuthMD5ChallengeMethod::new(password.as_bytes())),
            ),
            env: DefaultEnvironment::new(),
            buffer: Vec::new(),
        }
    }
}

#[cfg(feature = "tls")]
impl Authenticator<(AuthIdentityMethod, crate::layers::auth::AuthTlsMethod)> {
    pub fn new_tls(config: dummycert::TlsConfig) -> Self {
        use crate::layers::auth::AuthTlsMethod;
        Self {
            inner: EapLayer::new(
                AuthLayer::new()
                    .with(AuthIdentityMethod::new())
                    .with(AuthTlsMethod::new(config)),
            ),
            env: DefaultEnvironment::new(),
            buffer: Vec::new(),
        }
    }
}

impl<I> Authenticator<I>
where
    I: TupleById<dyn AuthInnerLayer>,
{
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

        AuthenticatorStepResult {
            status: match res.status {
                layers::eap_layer::EapStatus::Ok => AuthenticatorStepStatus::Ok,
                layers::eap_layer::EapStatus::Success => AuthenticatorStepStatus::Finished,
                layers::eap_layer::EapStatus::Failed(_) => AuthenticatorStepStatus::Error,
                layers::eap_layer::EapStatus::InternalError => AuthenticatorStepStatus::Error,
            },
            response: res.message.map(|m| m.slice().to_vec()),
        }
    }
}
