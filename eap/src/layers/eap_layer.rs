use crate::{
    message::{Message, MessageCode, MessageContent},
    EapEnvironment,
};

pub struct EapLayer<N> {
    state: State,
    // Count of invalid messages received,
    // fail if it exceeds max_invalid_message_count
    invalid_message_count: u8,
    next_id: u8,
    next_layer: N,
}

enum State {
    Start,
    Idle,
    RequestSent {
        expected_id: u8,
        retransmission_count: u8,
        last_message: Message,
    },
    Finished,
    Failed,
}

pub trait InnerLayer {
    fn is_peer(&self) -> bool;
    fn is_auth(&self) -> bool {
        !self.is_peer()
    }

    fn step(&mut self, input: InnerLayerInput, env: &mut dyn EapEnvironment) -> InnerLayerOutput {
        match input {
            InnerLayerInput::Start => self.start(env),
            InnerLayerInput::Recv(msg) => self.recv(msg, env),
        }
    }

    fn start(&mut self, env: &mut dyn EapEnvironment) -> InnerLayerOutput;

    fn recv(&mut self, _msg: Message, _env: &mut dyn EapEnvironment) -> InnerLayerOutput {
        unimplemented!();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerLayerInput {
    Start,
    Recv(Message),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerLayerOutput {
    Noop,
    Send(MessageContent),
    Finished,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapOutput {
    pub status: EapStatus,
    pub timeout: TimeoutPolicy,
    pub message: Option<Message>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EapStatus {
    Ok,
    Success,            // Conversation has ended successfully
    InternalError,      // Internal error
    Failed(StateError), // Conversation has ended with an error
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutPolicy {
    Set,
    Cancel,
    Noop,
}

impl EapOutput {
    fn send(message: Message, with_timeout: bool) -> Self {
        EapOutput {
            status: EapStatus::Ok,
            timeout: if with_timeout {
                TimeoutPolicy::Set
            } else {
                TimeoutPolicy::Cancel
            },
            message: Some(message),
        }
    }

    fn noop() -> Self {
        EapOutput {
            status: EapStatus::Ok,
            timeout: TimeoutPolicy::Noop,
            message: None,
        }
    }

    fn success(notify: Option<Message>) -> Self {
        EapOutput {
            status: EapStatus::Success,
            timeout: TimeoutPolicy::Cancel,
            message: notify,
        }
    }

    fn failed(error: StateError, notify: Option<Message>) -> Self {
        EapOutput {
            status: EapStatus::Failed(error),
            timeout: TimeoutPolicy::Cancel,
            message: notify,
        }
    }

    fn internal_error(notify: Option<Message>) -> Self {
        EapOutput {
            status: EapStatus::InternalError,
            timeout: TimeoutPolicy::Cancel,
            message: notify,
        }
    }
}

pub enum EapInput<'a> {
    Start,
    Receive(&'a [u8]),
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub enum StateError {
    UnexpectedMessage,
    InvalidMessage,
    ProtocolError,
    // This event is invalid in the current state
    InvalidEvent,
    /// The conversation has ended
    EndOfConversation,
}

impl<N: InnerLayer> EapLayer<N> {
    pub fn new(inner: N) -> Self {
        EapLayer {
            next_id: rand::random(), // TODO: Check RFC,
            state: State::Start,
            next_layer: inner,
            invalid_message_count: 0,
        }
    }

    pub fn step(&mut self, input: &EapInput, env: &mut dyn EapEnvironment) -> EapOutput {
        match input {
            EapInput::Start => self.start(env),
            EapInput::Receive(msg) => self.receive(msg, env),
            EapInput::Timeout => self.timeout(env),
        }
    }

    pub fn start(&mut self, env: &mut dyn EapEnvironment) -> EapOutput {
        match &self.state {
            State::Start => {
                self.state = State::Idle;
                let res = self.next_layer.start(env);
                self.process_result(res, env)
            }
            _ => EapOutput::internal_error(None),
        }
    }

    pub fn receive(&mut self, message: &[u8], env: &mut dyn EapEnvironment) -> EapOutput {
        match &self.state {
            State::Start | State::Idle => {
                // Silently drop the message, no request has been sent yet
                self.on_invalid_message(env)
            }
            State::RequestSent { expected_id, .. } => match Message::parse(message) {
                // Duplicate messages are ignored rfc3748 3.1.5
                Ok(msg) if self.next_layer.is_auth() => {
                    // Check if the message is a response to the last request
                    if msg.identifier != *expected_id {
                        return self.on_invalid_message(env);
                    }

                    // Auth layer should only receive responses or failure messages
                    if msg.code != MessageCode::Response {
                        return self.on_invalid_message(env);
                    }

                    if msg.code == MessageCode::Failure {
                        self.state = State::Failed;
                        return EapOutput::failed(StateError::EndOfConversation, None);
                    }

                    let res = self.next_layer.recv(msg, env);
                    self.process_result(res, env)
                }
                Ok(msg) if self.next_layer.is_peer() => {
                    if msg.identifier != *expected_id {
                        // Auth layer expects a retranmission of the last request
                        return self.retransmit(env);
                    }

                    // While Peer layer can receive everything but responses
                    if msg.code != MessageCode::Response {
                        return self.on_invalid_message(env);
                    }

                    if msg.code == MessageCode::Failure {
                        self.state = State::Failed;
                        return EapOutput::failed(StateError::EndOfConversation, None);
                    }

                    if msg.code == MessageCode::Success {
                        self.state = State::Finished;
                        return EapOutput::success(None);
                    }

                    let res = self.next_layer.recv(msg, env);
                    self.process_result(res, env)
                }
                Ok(_) => {
                    unreachable!(); // Inner layer must be either auth or peer
                }
                Err(_e) => self.on_invalid_message(env),
            },
            State::Finished => EapOutput::success(None),
            State::Failed => EapOutput::failed(StateError::EndOfConversation, None),
        }
    }

    pub fn timeout(&mut self, env: &mut dyn EapEnvironment) -> EapOutput {
        match self.state {
            State::RequestSent { .. } => {
                if self.next_layer.is_auth() {
                    self.retransmit(env)
                } else {
                    EapOutput::noop()
                }
            }
            State::Finished => EapOutput::success(None),
            State::Failed => EapOutput::failed(StateError::EndOfConversation, None),
            _ => EapOutput::noop(),
        }
    }

    fn retransmit(&mut self, env: &mut dyn EapEnvironment) -> EapOutput {
        match &self.state {
            State::RequestSent {
                retransmission_count,
                last_message,
                ..
            } => {
                if *retransmission_count >= env.max_retransmit_count() {
                    return self.on_fail(StateError::InvalidMessage, env);
                }

                EapOutput::send(
                    last_message.clone(),
                    // Set timeout for retransmission
                    self.next_layer.is_auth(),
                )
            }
            _ => self.on_invalid_message(env),
        }
    }

    fn on_invalid_message(&mut self, env: &mut dyn EapEnvironment) -> EapOutput {
        self.invalid_message_count += 1;
        if self.invalid_message_count >= env.max_invalid_message_count() {
            return self.on_fail(StateError::InvalidMessage, env);
        }

        EapOutput::noop()
    }

    fn on_fail(&mut self, reason: StateError, _env: &mut dyn EapEnvironment) -> EapOutput {
        self.state = State::Failed;
        EapOutput::failed(
            reason,
            Some(Message::new(MessageCode::Failure, self.next_id, &[])),
        )
    }

    fn process_result(&mut self, res: InnerLayerOutput, env: &mut dyn EapEnvironment) -> EapOutput {
        match dbg!(res) {
            InnerLayerOutput::Noop => EapOutput::noop(),
            InnerLayerOutput::Send(msg) => self.send_message(msg, env),
            InnerLayerOutput::Finished => {
                self.state = State::Finished;
                if self.next_layer.is_auth() {
                    // Notify Client
                    EapOutput::success(Some(Message::new(MessageCode::Success, self.next_id, &[])))
                } else {
                    EapOutput::success(None)
                }
            }
            InnerLayerOutput::Failed => {
                self.state = State::Failed;
                EapOutput::failed(StateError::EndOfConversation, None)
            }
        }
    }

    fn send_message(&mut self, msg: MessageContent, env: &mut dyn EapEnvironment) -> EapOutput {
        let code = if self.next_layer.is_auth() {
            MessageCode::Request
        } else {
            MessageCode::Response
        };

        let identifier = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let message = Message::new(code, identifier, &msg.data);
        self.state = State::RequestSent {
            expected_id: identifier,
            retransmission_count: 0,
            last_message: message.clone(),
        };

        EapOutput::send(message, self.next_layer.is_auth())
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use crate::DefaultEnvironment;

    pub use super::*;

    type DummyPeerLayer<F> = DummyInnerLayer<false, F>;
    type DummyAuthLayer<F> = DummyInnerLayer<true, F>;

    struct DummyInnerLayer<const AUTH: bool, F> {
        process: F,
    }

    impl<const AUTH: bool, F> DummyInnerLayer<AUTH, F> {
        pub fn new(process: F) -> Self {
            Self { process }
        }
    }

    impl<const AUTH: bool, F> InnerLayer for DummyInnerLayer<AUTH, F>
    where
        F: Fn(&InnerLayerInput, &mut dyn EapEnvironment) -> InnerLayerOutput,
    {
        fn is_auth(&self) -> bool {
            AUTH
        }

        fn is_peer(&self) -> bool {
            !AUTH
        }

        fn start(&mut self, env: &mut dyn EapEnvironment) -> InnerLayerOutput {
            (self.process)(&InnerLayerInput::Start, env)
        }

        fn recv(&mut self, msg: Message, env: &mut dyn EapEnvironment) -> InnerLayerOutput {
            (self.process)(&InnerLayerInput::Recv(msg), env)
        }
    }

    #[test]
    fn test_garbage_in() {
        let mut env = DefaultEnvironment::new();

        // TODO;
    }
}
