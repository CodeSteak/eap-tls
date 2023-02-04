use crate::{
    message::{Message, MessageCode, MessageContent},
    EapEnvironment,
};

pub struct EapLayer<N> {
    state: State,
    // Count of invalid messages received,
    // fail if it exceeds max_invalid_message_count
    invalid_message_count: u16,
    timed_out_count: u16,
    next_id: u8,
    next_layer: N,
}

enum State {
    Start,
    Idle,
    MessagePending {
        expected_id: u8,
        retransmission_count: u16,
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

    fn can_succeed(&self) -> bool;

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
    pub message: Option<Message>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EapStatus {
    Ok,
    Success,            // Conversation has ended successfully
    InternalError,      // Internal error
    Failed(StateError), // Conversation has ended with an error
}

impl EapStatus {
    fn failed(self) -> bool {
        match self {
            EapStatus::Failed(_) => true,
            _ => false,
        }
    }
}

impl EapOutput {
    fn send(message: Message, with_timeout: bool) -> Self {
        EapOutput {
            status: EapStatus::Ok,
            message: Some(message),
        }
    }

    fn noop() -> Self {
        EapOutput {
            status: EapStatus::Ok,
            message: None,
        }
    }

    fn success(notify: Option<Message>) -> Self {
        EapOutput {
            status: EapStatus::Success,
            message: notify,
        }
    }

    fn failed(error: StateError, notify: Option<Message>) -> Self {
        EapOutput {
            status: EapStatus::Failed(error),
            message: notify,
        }
    }

    fn internal_error(notify: Option<Message>) -> Self {
        EapOutput {
            status: EapStatus::InternalError,
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
    Timeout,
}

impl<N: InnerLayer> EapLayer<N> {
    pub fn new(inner: N) -> Self {
        EapLayer {
            next_id: rand::random(), // TODO: Check RFC,
            state: State::Start,
            next_layer: inner,
            invalid_message_count: 0,
            timed_out_count: 0,
        }
    }

    /// Note: If there is no event to process after a certain amount of time, send a timeout event
    /// to the state machine. This Timeout should be a few milliseconds. Too many Timeout will
    /// cause the state machine to fail. This value can be adjusted in the environment.
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
        // Reset Timeout counter
        self.timed_out_count = 0;

        match &self.state {
            State::Start | State::Idle if self.next_layer.is_auth() => {
                // Silently drop the message, no request has been sent yet
                self.on_invalid_message(env)
            }
            State::Start | State::Idle => {
                // if peer
                match Message::parse(message) {
                    Ok(msg) if msg.code == MessageCode::Request => {
                        self.invalid_message_count = 0;
                        self.next_id = msg.identifier;
                        let res = self.next_layer.recv(msg, env);
                        self.process_result(res, env)
                    }
                    Ok(msg) if msg.code == MessageCode::Failure => {
                        // TODO: Ask inner layer if it is ok to end the conversation
                        self.state = State::Failed;
                        EapOutput::failed(StateError::EndOfConversation, None)
                    }
                    _ => self.on_invalid_message(env),
                }
            }
            State::MessagePending { expected_id, .. } => match Message::parse(message) {
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
                    if msg.identifier == *expected_id {
                        // a.k.a expected_id is the last id sent by the peer
                        // Auth layer expects a retranmission of the last request
                        return self.retransmit(env);
                    }

                    if msg.identifier != self.next_id {
                        // Message id is not valid
                        return self.on_invalid_message(env);
                    }

                    // While Peer layer can receive everything but responses
                    if msg.code == MessageCode::Response {
                        return self.on_invalid_message(env);
                    }

                    if msg.code == MessageCode::Failure {
                        self.state = State::Failed;
                        return EapOutput::failed(StateError::EndOfConversation, None);
                    }

                    if msg.code == MessageCode::Success && self.next_layer.can_succeed() {
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
            State::MessagePending { .. } => {
                if self.next_layer.is_auth() {
                    self.retransmit(env)
                } else {
                    self.on_timeout(env)
                }
            }
            State::Finished => EapOutput::success(None),
            State::Failed => EapOutput::failed(StateError::EndOfConversation, None),
            _ => self.on_timeout(env),
        }
    }

    fn on_timeout(&mut self, env: &mut dyn EapEnvironment) -> EapOutput {
        self.timed_out_count += 1;
        if self.timed_out_count >= env.max_timeout_count() {
            self.state = State::Failed;
            return EapOutput::failed(
                StateError::Timeout,
                Some(Message::new(MessageCode::Failure, self.next_id, &[])),
            );
        }

        EapOutput::success(None)
    }

    fn retransmit(&mut self, env: &mut dyn EapEnvironment) -> EapOutput {
        match &mut self.state {
            State::MessagePending {
                retransmission_count,
                last_message,
                ..
            } => {
                if *retransmission_count >= env.max_retransmit_count() {
                    return self.on_fail(StateError::Timeout, env);
                }

                *retransmission_count += 1;

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
        match res {
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
        self.state = State::MessagePending {
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
    use std::panic::Location;

    pub use super::*;

    struct DummyInnerLayer {
        is_auth: bool,
        is_peer: bool,
        counter: u8,
        messages: Vec<MessageContent>,
    }

    impl DummyInnerLayer {
        pub fn new(is_auth: bool) -> Self {
            Self {
                is_auth,
                is_peer: !is_auth,
                counter: 0,
                messages: Vec::new(),
            }
        }

        pub fn with_messages(is_auth: bool, messages: &[MessageContent]) -> Self {
            Self {
                is_auth,
                is_peer: !is_auth,
                counter: 0,
                messages: messages.to_vec(),
            }
        }
    }

    impl InnerLayer for DummyInnerLayer {
        fn start(&mut self, env: &mut dyn EapEnvironment) -> InnerLayerOutput {
            if self.is_auth {
                InnerLayerOutput::Send(MessageContent::new(&[0, self.counter]))
            } else {
                InnerLayerOutput::Noop
            }
        }

        fn recv(&mut self, msg: Message, env: &mut dyn EapEnvironment) -> InnerLayerOutput {
            if self.is_auth {
                assert_eq!(msg.code, MessageCode::Response);
            } else {
                assert_eq!(msg.code, MessageCode::Request);
            }
            assert_eq!(msg.data.len(), 2);
            self.counter += 1;
            InnerLayerOutput::Send(MessageContent::new(&[msg.data[0], self.counter]))
        }

        fn is_peer(&self) -> bool {
            self.is_peer
        }

        fn can_succeed(&self) -> bool {
            true
        }
    }

    #[track_caller]
    fn assert_output(output: EapOutput, expected: EapOutput) {
        assert_eq!(output.status, expected.status, "Status mismatch");

        // ignore message id
        if let Some(msg) = &expected.message {
            if let Some(out_msg) = &output.message {
                assert_eq!(msg.code, out_msg.code);
                assert_eq!(msg.data, out_msg.data);
            } else {
                panic!("Expected message but got None");
            }
        } else {
            assert_eq!(output.message, None);
        }
    }

    #[test]
    /// Test simple dialog
    fn dialog_peer() {
        let mut env = DefaultEnvironment::new();
        let mut layer = EapLayer::new(DummyInnerLayer::new(false));

        assert_output(
            layer.start(&mut env),
            EapOutput {
                message: None,
                status: EapStatus::Ok,
            },
        );

        assert_output(
            layer.receive(
                &Message::new(MessageCode::Request, 42, &[23, 0]).to_bytes(),
                &mut env,
            ),
            EapOutput {
                message: Some(Message::new(MessageCode::Response, 42, &[23, 1])),
                status: EapStatus::Ok,
            },
        );

        // Throw away the message, the Message Id is Wrong
        assert_output(
            layer.receive(
                &Message::new(MessageCode::Success, 44, &[]).to_bytes(),
                &mut env,
            ),
            EapOutput {
                message: None,
                status: EapStatus::Ok,
            },
        );

        // Now send the correct message
        assert_output(
            layer.receive(
                &Message::new(MessageCode::Success, 43, &[]).to_bytes(),
                &mut env,
            ),
            EapOutput {
                message: None,
                status: EapStatus::Success,
            },
        );
    }

    #[test]
    /// An Conversation should be aborted if the peer/auth sends too many invalid messages.
    fn abort_on_too_many_invalid_messages() {
        let mut env = DefaultEnvironment::new();
        let mut layer = EapLayer::new(DummyInnerLayer::new(true));

        let _ = layer.start(&mut env);

        let peer_msg = &b"Not a valid EAP message"[..];
        for _ in 1..env.max_invalid_message_count() {
            assert_output(
                layer.receive(&peer_msg, &mut env),
                EapOutput {
                    message: None,
                    status: EapStatus::Ok,
                },
            );
        }

        let output = layer.receive(&peer_msg, &mut env);
        assert!(output.status.failed());
    }

    #[test]
    /// An EAP peer must abort after too many retransmissions.
    fn test_retransmit_peer() {
        let mut env = DefaultEnvironment::new();

        let mut layer = EapLayer::new(DummyInnerLayer::new(false));

        assert_output(
            layer.start(&mut env),
            EapOutput {
                message: None,
                status: EapStatus::Ok,
            },
        );

        let peer_msg = Message::new(MessageCode::Request, 0, &[0, 0]).to_bytes();

        for i in 0..env.max_retransmit_count() + 1 {
            // +1 because the first message is not a retransmission
            assert_output(
                layer.receive(&peer_msg, &mut env),
                EapOutput {
                    message: Some(Message::new(MessageCode::Response, 0, &[0, 1])),
                    status: EapStatus::Ok,
                },
            );
        }

        let o = layer.receive(&peer_msg, &mut env);
        assert!(o.status.failed());
    }

    #[test]
    /// An EAP Auth must abort after too many retransmissions.
    fn test_retransmit_auth() {
        let mut env = DefaultEnvironment::new();

        let mut layer = EapLayer::new(DummyInnerLayer::new(true));

        assert_output(
            layer.start(&mut env),
            EapOutput {
                message: Some(Message::new(MessageCode::Request, 0, &[0, 0])),
                status: EapStatus::Ok,
            },
        );

        for _ in 0..env.max_retransmit_count() {
            assert_output(
                layer.timeout(&mut env),
                EapOutput {
                    message: Some(Message::new(MessageCode::Request, 0, &[0, 0])),
                    status: EapStatus::Ok,
                },
            );
        }

        assert_output(
            layer.timeout(&mut env),
            EapOutput {
                message: Some(Message::new(MessageCode::Failure, 0, &[])),
                status: EapStatus::Failed(StateError::Timeout),
            },
        );
    }
}
