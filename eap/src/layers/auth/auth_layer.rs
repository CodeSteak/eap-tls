use std::vec;

use crate::{
    message::{Message, MessageCode, MessageContent},
    EapEnvironment,
};

use crate::layers::eap_layer::{InnerLayer as ThisLayer, InnerLayerOutput as ThisLayerResult};

pub struct AuthLayer<I: InnerLayer> {
    state: State,
    next_layer: I,
    candidates: Vec<I>, // <- should be okay for now
}

pub enum AuthResult {
    Ok,
}

enum State {
    Default,
    Finished,
    Failed,
}

pub const METHOD_CLIENT_PROPOSAL: u8 = 3;

pub struct RecvMeta<'a> {
    pub message: &'a Message,
}

pub trait InnerLayer: Clone {
    /* */
    fn method_identifier(&self) -> u8;
    fn start(&mut self, env: &mut dyn EapEnvironment) -> InnerResult;
    fn recv(&mut self, msg: &[u8], meta: &RecvMeta, env: &mut dyn EapEnvironment) -> InnerResult;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerResult {
    Noop,
    Send(MessageContent),
    Finished,
    Failed,
    NextLayer,
}

impl<I: InnerLayer> ThisLayer for AuthLayer<I> {
    fn is_peer(&self) -> bool {
        false
    }

    fn start(&mut self, env: &mut dyn EapEnvironment) -> ThisLayerResult {
        let res = self.next_layer.start(env);
        self.process_result(res, env)
    }

    fn recv(&mut self, msg: Message, env: &mut dyn EapEnvironment) -> ThisLayerResult {
        if msg.code != MessageCode::Response {
            return ThisLayerResult::Failed;
        }

        if msg.data.len() < 1 {
            // Message Too Short
            return ThisLayerResult::Failed;
        }

        let method_identifier = msg.data[0];
        if method_identifier == METHOD_CLIENT_PROPOSAL {
            for candidate in self.candidates.iter() {
                if msg.data[1..].contains(&candidate.method_identifier()) {
                    self.next_layer = candidate.clone();

                    let res = self.next_layer.start(env);
                    return self.process_result(res, env);
                }
            }

            return ThisLayerResult::Failed; // <- no matching method
        }

        if method_identifier != self.next_layer.method_identifier() {
            return ThisLayerResult::Failed;
        }

        let res = self
            .next_layer
            .recv(&msg.data[1..], &RecvMeta { message: &msg }, env);
        self.process_result(res, env)
    }
}

impl<I: InnerLayer> AuthLayer<I> {
    pub fn new(candidates: Vec<I>) -> Self {
        assert!(candidates.len() > 0);
        AuthLayer {
            state: State::Default {},
            next_layer: candidates[0].clone(),
            candidates: candidates,
        }
    }

    fn process_result(
        &mut self,
        res: InnerResult,
        env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        match dbg!(res) {
            InnerResult::Noop => ThisLayerResult::Noop,
            InnerResult::Send(msg) => {
                let id = self.next_layer.method_identifier();
                let data = add_message_identifier_to_data(id, msg.data);
                ThisLayerResult::Send(MessageContent { data })
            }
            InnerResult::Finished => ThisLayerResult::Finished,
            InnerResult::Failed => ThisLayerResult::Failed,
            InnerResult::NextLayer => {
                if self.candidates.len() > 1 {
                    // TODO: select properly
                    self.next_layer = self.candidates[1].clone();
                    let res = self.next_layer.start(env);
                    self.process_result(res, env)
                } else {
                    ThisLayerResult::Failed // <- Internal Issue
                }
            }
        }
    }
}

fn add_message_identifier_to_data(id: u8, data: Vec<u8>) -> Vec<u8> {
    let mut buf = vec![];
    buf.extend_from_slice(&[id]);
    buf.extend_from_slice(&data);
    buf
}

#[cfg(test)]
mod tests {
    /*use crate::layers::auth::identity::AuthIdentityMethod;

    use super::*;

    struct DummyEnv {
        name: Option<Vec<u8>>,
    }

    impl DummyEnv {
        fn new() -> Self {
            DummyEnv { name: None }
        }
    }

    impl EapEnvironment for DummyEnv {
        fn set_name(&mut self, name: &[u8]) {
            self.name = Some(name.to_vec());
        }

        fn name(&self) -> Option<&[u8]> {
            self.name.as_ref().map(|v| v.as_slice())
        }
    }

    #[test]
    fn test_does_identity() {
        let mut layer = AuthLayer::new(vec![AuthIdentityMethod::new()]);
        let mut env = DummyEnv::new();

        assert_eq!(
            layer.start(&mut env),
            ThisLayerResult::Send(MessageContent { data: vec![1] })
        );

        let _ = layer.recv(
            Message::new(MessageCode::Response, 0x42, &[0x01, 0x02, 0x03]),
            &mut env,
        );

        assert_eq!(env.name(), Some(&[0x02, 0x03][..]));
    }*/
}
