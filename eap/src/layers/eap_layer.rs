use crate::{
    message::{Message, MessageCode},
    EapEnvironment, EapEnvironmentResponse, MessageBuilder, ResponseMessage,
};

#[cfg(not(feature = "std"))]
use core as std;

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
    },
    Finished,
    Failed,
}

pub trait PeerAuthLayer {
    fn is_peer(&self) -> bool;
    fn is_auth(&self) -> bool {
        !self.is_peer()
    }

    fn can_succeed(&mut self) -> bool;

    fn step<'a>(
        &mut self,
        input: PeerAuthLayerInput,
        env: &'a mut dyn EapEnvironment,
    ) -> PeerAuthLayerResult<'a> {
        match input {
            PeerAuthLayerInput::Start => self.start(env),
            PeerAuthLayerInput::Recv(msg) => self.recv(&msg, env),
        }
    }

    fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> PeerAuthLayerResult<'a>;

    fn recv<'a>(
        &mut self,
        _msg: &Message,
        _env: &'a mut dyn EapEnvironment,
    ) -> PeerAuthLayerResult<'a>;
}

#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAuthLayerInput<'a> {
    Start,
    Recv(Message<'a>),
}

pub enum PeerAuthLayerResult<'a> {
    Noop(&'a mut dyn EapEnvironment),
    Send(MessageBuilder<'a>),
    Finished(&'a mut dyn EapEnvironment),
    Failed(&'a mut dyn EapEnvironment),
}

impl<'a> PartialEq for PeerAuthLayerResult<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PeerAuthLayerResult::Noop(_), PeerAuthLayerResult::Noop(_)) => true,
            (PeerAuthLayerResult::Send(a), PeerAuthLayerResult::Send(b)) => a == b,
            (PeerAuthLayerResult::Finished(_), PeerAuthLayerResult::Finished(_)) => true,
            (PeerAuthLayerResult::Failed(_), PeerAuthLayerResult::Failed(_)) => true,
            _ => false,
        }
    }
}

impl<'a> Eq for PeerAuthLayerResult<'a> {}

impl<'a> std::fmt::Debug for PeerAuthLayerResult<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAuthLayerResult::Noop(_) => write!(f, "Noop"),
            PeerAuthLayerResult::Send(msg) => write!(f, "Send({:?})", msg.slice()),
            PeerAuthLayerResult::Finished(_) => write!(f, "Finished"),
            PeerAuthLayerResult::Failed(_) => write!(f, "Failed"),
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct EapOutput<'a> {
    pub status: EapStatus,
    pub message: Option<ResponseMessage<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EapStatus {
    Ok,
    Success,                     // Conversation has ended successfully
    InternalError(&'static str), // Internal error
    Failed(StateError),          // Conversation has ended with an error
}

#[allow(unused)]
impl EapStatus {
    fn failed(self) -> bool {
        matches!(self, EapStatus::Failed(_))
    }
}

impl<'a> EapOutput<'a> {
    fn send(message: ResponseMessage<'a>) -> Self {
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

    fn success(notify: Option<ResponseMessage<'a>>) -> Self {
        EapOutput {
            status: EapStatus::Success,
            message: notify,
        }
    }

    fn failed(error: StateError, notify: Option<ResponseMessage<'a>>) -> Self {
        EapOutput {
            status: EapStatus::Failed(error),
            message: notify,
        }
    }

    fn internal_error(message: &'static str, notify: Option<ResponseMessage<'a>>) -> Self {
        EapOutput {
            status: EapStatus::InternalError(message),
            message: notify,
        }
    }
}

#[allow(unused)]
pub enum EapInput<'a> {
    Start,
    Receive(&'a [u8]),
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub enum StateError {
    InvalidMessage,
    EndOfConversation,
    Timeout,
}

impl<N: PeerAuthLayer> EapLayer<N> {
    pub fn new(inner: N) -> Self {
        EapLayer {
            next_id: 0, // gets initialized in start()
            state: State::Start,
            next_layer: inner,
            invalid_message_count: 0,
            timed_out_count: 0,
        }
    }

    #[allow(unused)]
    pub fn has_started(&self) -> bool {
        !matches!(self.state, State::Start)
    }

    #[allow(unused)]
    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Finished)
    }

    #[allow(unused)]
    pub fn is_failed(&self) -> bool {
        matches!(self.state, State::Failed)
    }

    #[allow(unused)]
    /// Note: If there is no event to process after a certain amount of time, send a timeout event
    /// to the state machine. This Timeout should be a few milliseconds. Too many Timeout will
    /// cause the state machine to fail. This value can be adjusted in the environment.
    pub fn step<'a>(&mut self, input: &EapInput, env: &'a mut dyn EapEnvironment) -> EapOutput<'a> {
        match input {
            EapInput::Start => self.start(env),
            EapInput::Receive(msg) => self.receive(msg, env),
            EapInput::Timeout => self.timeout(env),
        }
    }

    pub fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> EapOutput<'a> {
        if self.next_layer.is_auth() {
            let next_id = &mut [0u8];
            env.fill_random(&mut next_id[..]);
            self.next_id = next_id[0];
        }

        match &self.state {
            State::Start => {
                self.state = State::Idle;
                let res = self.next_layer.start(env);
                self.process_result(res)
            }
            _ => EapOutput::internal_error(
                "EAP state machine is not in the Start state, cannot start",
                None,
            ),
        }
    }

    pub fn receive<'a>(
        &mut self,
        message: &[u8],
        env: &'a mut dyn EapEnvironment,
    ) -> EapOutput<'a> {
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
                        let res = self.next_layer.recv(&msg, env);
                        self.process_result(res)
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

                    let res = self.next_layer.recv(&msg, env);
                    self.process_result(res)
                }
                Ok(msg) if self.next_layer.is_peer() => {
                    // Sucess messages have other next_id ...
                    // because this code would be to easy otherwise
                    if msg.code == MessageCode::Success
                        && self.next_layer.can_succeed()
                        && msg.identifier == self.next_id.wrapping_sub(1)
                    {
                        self.state = State::Finished;
                        return EapOutput::success(None);
                    }

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

                    let res = self.next_layer.recv(&msg, env);
                    self.process_result(res)
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

    pub fn timeout<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> EapOutput<'a> {
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

    fn on_timeout<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> EapOutput<'a> {
        self.timed_out_count += 1;
        if self.timed_out_count >= env.max_timeout_count() {
            self.state = State::Failed;
            return EapOutput::failed(
                StateError::Timeout,
                Some(env.respond_with(MessageCode::Failure, self.next_id, &[])),
            );
        }

        EapOutput::noop()
    }

    fn retransmit<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> EapOutput<'a> {
        match &mut self.state {
            State::MessagePending {
                retransmission_count,
                ..
            } => {
                if *retransmission_count >= env.max_retransmit_count() {
                    return self.on_fail(StateError::Timeout, env);
                }

                *retransmission_count += 1;

                match env.last_message() {
                    Ok(msg) => EapOutput::send(msg),
                    _ => {
                        EapOutput::internal_error("Last message not found, can't retransmit", None)
                    }
                }
            }
            _ => self.on_invalid_message(env),
        }
    }

    fn on_invalid_message<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> EapOutput<'a> {
        self.invalid_message_count += 1;
        if self.invalid_message_count >= env.max_invalid_message_count() {
            return self.on_fail(StateError::InvalidMessage, env);
        }

        EapOutput::noop()
    }

    fn on_fail<'a>(
        &mut self,
        reason: StateError,
        env: &'a mut dyn EapEnvironment,
    ) -> EapOutput<'a> {
        self.state = State::Failed;
        EapOutput::failed(
            reason,
            Some(env.respond_with(MessageCode::Failure, self.next_id, &[])),
        )
    }

    fn process_result<'a>(&mut self, res: PeerAuthLayerResult<'a>) -> EapOutput<'a> {
        match res {
            PeerAuthLayerResult::Noop(_) => EapOutput::noop(),
            PeerAuthLayerResult::Send(msg) => self.send_message(msg),
            PeerAuthLayerResult::Finished(env) => {
                self.state = State::Finished;
                if self.next_layer.is_auth() {
                    // Notify Client
                    // For success messages the identifier is the same as the last request.
                    // TODO: refactor `next_id to be `last_id`
                    self.next_id = self.next_id.wrapping_sub(1);

                    EapOutput::success(Some(env.respond_with(
                        MessageCode::Success,
                        self.next_id,
                        &[],
                    )))
                } else {
                    EapOutput::success(None)
                }
            }
            PeerAuthLayerResult::Failed(env) => {
                self.state = State::Failed;
                EapOutput::failed(
                    StateError::EndOfConversation,
                    Some(env.respond_with(MessageCode::Failure, self.next_id, &[])),
                )
            }
        }
    }

    fn send_message<'a>(&mut self, msg: MessageBuilder<'a>) -> EapOutput<'a> {
        let code = if self.next_layer.is_auth() {
            MessageCode::Request
        } else {
            MessageCode::Response
        };

        let identifier = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let message = msg.build(code, identifier);

        self.state = State::MessagePending {
            expected_id: identifier,
            retransmission_count: 0,
        };

        EapOutput::send(message)
    }
}

// Unit tests
#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use crate::DefaultEnvironment;

    pub use super::*;

    struct DummyInnerLayer {
        is_auth: bool,
        is_peer: bool,
        counter: u8,
    }

    impl DummyInnerLayer {
        pub fn new(is_auth: bool) -> Self {
            Self {
                is_auth,
                is_peer: !is_auth,
                counter: 0,
            }
        }
    }

    impl PeerAuthLayer for DummyInnerLayer {
        fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> PeerAuthLayerResult<'a> {
            if self.is_auth {
                PeerAuthLayerResult::Send(env.respond().write([0, self.counter].as_slice()))
            } else {
                PeerAuthLayerResult::Noop(env)
            }
        }

        fn recv<'a>(
            &mut self,
            msg: &Message,
            env: &'a mut dyn EapEnvironment,
        ) -> PeerAuthLayerResult<'a> {
            if self.is_auth {
                assert_eq!(msg.code, MessageCode::Response);
            } else {
                assert_eq!(msg.code, MessageCode::Request);
            }
            assert_eq!(msg.body.len(), 2);
            self.counter += 1;
            PeerAuthLayerResult::Send(env.respond().write([msg.body[0], self.counter].as_slice()))
        }

        fn is_peer(&self) -> bool {
            self.is_peer
        }

        fn can_succeed(&mut self) -> bool {
            true
        }
    }

    #[track_caller]
    fn assert_output(output: EapOutput, expected: EapOutput) {
        assert_eq!(output.status, expected.status, "Status mismatch");

        // ignore message id
        if let Some(msg) = &expected.message {
            if let Some(out_msg) = &output.message {
                assert_eq!(msg.as_ref(), out_msg.as_ref())
            } else {
                panic!("Expected message but got None");
            }
        } else {
            assert!(output.message.is_none());
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
                &Message::new(MessageCode::Request, 42, &[23, 0]).to_vec(),
                &mut env,
            ),
            EapOutput {
                message: Some(Message::new(MessageCode::Response, 42, &[23, 1]).into()),
                status: EapStatus::Ok,
            },
        );

        // Throw away the message, the Message Id is Wrong
        assert_output(
            layer.receive(
                &Message::new(MessageCode::Success, 44, &[]).to_vec(),
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
                &Message::new(MessageCode::Success, 42, &[]).to_vec(),
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
                layer.receive(peer_msg, &mut env),
                EapOutput {
                    message: None,
                    status: EapStatus::Ok,
                },
            );
        }

        let output = layer.receive(peer_msg, &mut env);
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

        let peer_msg = Message::new(MessageCode::Request, 0, &[0, 0]).to_vec();

        for _ in 0..env.max_retransmit_count() + 1 {
            // +1 because the first message is not a retransmission
            assert_output(
                layer.receive(&peer_msg, &mut env),
                EapOutput {
                    message: Some(Message::new(MessageCode::Response, 0, &[0, 1]).into()),
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

        layer.next_id = 0;

        assert_output(
            layer.start(&mut env),
            EapOutput {
                message: Some(Message::new(MessageCode::Request, 0, &[0, 0]).into()),
                status: EapStatus::Ok,
            },
        );

        for _ in 0..env.max_retransmit_count() {
            assert_output(
                layer.timeout(&mut env),
                EapOutput {
                    message: Some(Message::new(MessageCode::Request, 0, &[0, 0]).into()),
                    status: EapStatus::Ok,
                },
            );
        }

        assert_output(
            layer.timeout(&mut env),
            EapOutput {
                message: Some(Message::new(MessageCode::Failure, 1, &[]).into()),
                status: EapStatus::Failed(StateError::Timeout),
            },
        );
    }
}
