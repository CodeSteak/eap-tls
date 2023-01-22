use crate::{
    message::{Message, MessageCode, MessageContent},
    EapEnvironment,
};

pub struct EapLayer<N> {
    state: State,
    next_id: u8,
    next_layer: N,
}

enum State {
    Idle,
    RequestSent {
        expected_id: u8,
        restransmit_count: u8,
        last_message: Message,
    },
    Finished,
}

pub trait InnerLayer {
    fn is_peer(&self) -> bool;
    fn is_auth(&self) -> bool {
        !self.is_peer()
    }

    fn start(&mut self, env: &mut dyn EapEnvironment) -> InnerLayerResult;

    fn recv(&mut self, _msg: Message, _env: &mut dyn EapEnvironment) -> InnerLayerResult {
        unimplemented!();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerLayerResult {
    Noop,
    Send(MessageContent),
    Finished,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub enum StateResult {
    Ok,
    Finished,
    Failed(StateError),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub enum StateError {
    UnexpectedMessage,
    InvalidMessage,
    InternalError,
}

impl<N: InnerLayer> EapLayer<N> {
    pub fn new(inner: N) -> Self {
        EapLayer {
            next_id: rand::random(), // TODO: Check RFC,
            state: State::Idle,
            next_layer: inner,
        }
    }

    pub fn start(&mut self, env: &mut dyn EapEnvironment) -> StateResult {
        let res = self.next_layer.start(env);

        self.process_result(res, env)
    }

    pub fn receive(&mut self, message: &[u8], env: &mut dyn EapEnvironment) -> StateResult {
        match &self.state {
            State::Idle => StateResult::Failed(StateError::UnexpectedMessage),
            State::RequestSent { expected_id, .. } => match Message::parse(message) {
                Ok(msg) => {
                    // Check if the message is a response to the last request
                    if msg.identifier != *expected_id {
                        return StateResult::Failed(StateError::InvalidMessage);
                    }

                    // Auth layer should only receive responses
                    if self.next_layer.is_auth() && msg.code != MessageCode::Response {
                        return StateResult::Failed(StateError::InvalidMessage);
                    }

                    // While Peer layer should only receive requests
                    if self.next_layer.is_peer() && msg.code != MessageCode::Request {
                        return StateResult::Failed(StateError::InvalidMessage);
                    }

                    let res = self.next_layer.recv(msg, env);
                    return self.process_result(res, env);
                }
                Err(_e) => StateResult::Failed(StateError::InvalidMessage),
            },
            State::Finished => StateResult::Finished,
        }
    }

    pub fn timeout(&mut self, _env: &mut dyn EapEnvironment) -> StateResult {
        unimplemented!();
    }

    fn process_result(
        &mut self,
        res: InnerLayerResult,
        env: &mut dyn EapEnvironment,
    ) -> StateResult {
        match dbg!(res) {
            InnerLayerResult::Noop => StateResult::Ok,
            InnerLayerResult::Send(msg) => self.send_message(msg, env),
            InnerLayerResult::Finished => {
                if self.next_layer.is_auth() {
                    // Notify Client
                    env.send(&Message::new(MessageCode::Success, self.next_id, &[]).to_bytes());
                    self.next_id = self.next_id.wrapping_add(1);
                }

                StateResult::Finished
            }
            InnerLayerResult::Failed => {
                // TODO Double Check error handling
                env.send(&Message::new(MessageCode::Failure, self.next_id, &[]).to_bytes());
                self.next_id = self.next_id.wrapping_add(1);

                StateResult::Failed(StateError::InternalError)
            }
        }
    }

    fn send_message(&mut self, msg: MessageContent, env: &mut dyn EapEnvironment) -> StateResult {
        let code = if self.next_layer.is_auth() {
            MessageCode::Request
        } else {
            MessageCode::Response
        };

        let identifier = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let message = Message::new(code, identifier, &msg.data);

        env.send(&message.to_bytes());

        self.state = State::RequestSent {
            expected_id: identifier,
            restransmit_count: 0,
            last_message: message,
        };

        StateResult::Ok
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    pub use super::*;

    struct TestAuthLayer {
        is_peer: bool,
    }

    impl InnerLayer for TestAuthLayer {
        fn is_peer(&self) -> bool {
            self.is_peer
        }

        fn start(&mut self, _env: &mut dyn EapEnvironment) -> InnerLayerResult {
            InnerLayerResult::Send(MessageContent {
                data: vec![0x01, 0x02, 0x03],
            })
        }
    }

    struct TestEnvironment {
        sent_messages: Vec<Vec<u8>>,
    }

    impl TestEnvironment {
        fn drain(&mut self) -> Vec<Vec<u8>> {
            self.sent_messages.drain(..).collect()
        }
    }

    impl EapEnvironment for TestEnvironment {
        fn send(&mut self, msg: &[u8]) {
            self.sent_messages.push(msg.to_vec());
        }

        fn set_name(&mut self, _name: &[u8]) {
            unimplemented!();
        }

        fn name(&self) -> Option<&[u8]> {
            None
        }
    }

    #[test]
    fn basic_send() {
        let mut layer = EapLayer::new(TestAuthLayer { is_peer: true });

        let mut env = TestEnvironment {
            sent_messages: Vec::new(),
        };

        assert_eq!(layer.start(&mut env), StateResult::Ok);
        assert_eq!(env.drain(), Vec::<Vec<u8>>::new());

        //
    }
}
