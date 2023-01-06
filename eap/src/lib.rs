mod message;

struct EapStateMachine {
    role: EapRole,
    state: InternalState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalState {
    Discovery,
    EapAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EapRole {
    Peer,
    Server,
}

enum EapStatus {
    Ok,
    Finished,
    Failed,
}

enum EapError {
    InvalidMessage(message::MessageParseError),
    Other,
}

impl From<message::MessageParseError> for EapError {
    fn from(err: message::MessageParseError) -> Self {
        Self::InvalidMessage(err)
    }
}

trait EapEnvironment {
    fn received(&self) -> Option<&[u8]>;
    fn send(&mut self, data: &[u8]);
}

impl EapStateMachine {
    fn new(role: EapRole) -> Self {
        Self {
            role,
            state: InternalState::Discovery,
        }
    }

    fn step(&mut self, env: &mut dyn EapEnvironment) -> Result<EapStatus, EapError> {
        match self.role {
            EapRole::Peer => self.step_peer(env),
            EapRole::Server => self.step_server(env),
        }
    }

    fn step_peer(&mut self, env: &mut dyn EapEnvironment) -> Result<EapStatus, EapError> {
        unimplemented!()
    }

    fn step_server(&mut self, env: &mut dyn EapEnvironment) -> Result<EapStatus, EapError> {
        unimplemented!()
    }
}
