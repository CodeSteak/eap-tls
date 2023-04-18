use crate::{
    layers::{
        self,
        auth::{AuthIdentityMethod, AuthMD5ChallengeMethod, AuthMethodLayer},
        mux::TupleById,
        AuthLayer, EapLayer,
    },
    DefaultEnvironment, EapWrapper,
};

pub use super::EapStepResult as AuthenticatorStepResult;
pub use super::EapStepStatus as AuthenticatorStepStatus;

pub struct Authenticator<I> {
    env: DefaultEnvironment,
    inner: EapLayer<AuthLayer<I>>,
    buffer: Vec<u8>,
}

impl Authenticator<(AuthIdentityMethod, AuthMD5ChallengeMethod)> {
    pub fn new_password(password: &str) -> Self {
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
impl Authenticator<(AuthIdentityMethod, crate::eap_rustls::AuthTlsMethod)> {
    pub fn new_tls(config: dummycert::TlsConfig) -> Self {
        use crate::eap_rustls::AuthTlsMethod;
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

impl<I> EapWrapper for Authenticator<I>
where
    I: TupleById<dyn AuthMethodLayer>,
{
    fn receive(&mut self, data: &[u8]) {
        self.buffer = data.to_vec();
    }

    fn step(&mut self) -> AuthenticatorStepResult<'_> {
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
                layers::eap_layer::EapStatus::InternalError(_) => AuthenticatorStepStatus::Error,
            },
            response: res.message.map(|m| m.into_slice()),
        }
    }
}
