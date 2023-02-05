use std::vec;

use crate::{
    message::{Message, MessageCode, MessageContent},
    EapEnvironment,
};

use crate::layers::eap_layer::{InnerLayer as ThisLayer, InnerLayerOutput as ThisLayerResult};

#[derive(Clone)]
pub struct AuthLayer<I: AuthInnerLayer> {
    peer_has_sent_nak: bool, // RFC allows only one NAK per session
    next_layer: I,
    candidates: Vec<I>, // <- should be okay for now
}

pub const METHOD_CLIENT_PROPOSAL: u8 = 3;

pub struct RecvMeta<'a> {
    pub message: &'a Message,
}

pub trait AuthInnerLayer: Clone {
    fn method_identifier(&self) -> u8;
    fn start(&mut self, env: &mut dyn EapEnvironment) -> AuthInnerLayerResult;
    fn recv(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        env: &mut dyn EapEnvironment,
    ) -> AuthInnerLayerResult;
    fn selectable_by_nak(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthInnerLayerResult {
    Send(MessageContent),
    Finished,
    Failed,
    NextLayer,
}

impl<I: AuthInnerLayer> ThisLayer for AuthLayer<I> {
    fn is_peer(&self) -> bool {
        false
    }

    fn start(&mut self, env: &mut dyn EapEnvironment) -> ThisLayerResult {
        let res = self.next_layer.start(env);
        self.process_result(res, env)
    }

    fn recv(&mut self, msg: &Message, env: &mut dyn EapEnvironment) -> ThisLayerResult {
        if msg.code != MessageCode::Response {
            return ThisLayerResult::Failed;
        }

        if msg.data.is_empty() {
            // Message Too Short
            return ThisLayerResult::Failed;
        }

        let method_identifier = msg.data[0];
        if method_identifier == METHOD_CLIENT_PROPOSAL {
            if self.peer_has_sent_nak {
                // Protocol Violation
                return ThisLayerResult::Failed;
            }
            self.peer_has_sent_nak = true;

            for candidate in self.candidates.iter() {
                if candidate.selectable_by_nak()
                    && msg.data[1..].contains(&candidate.method_identifier())
                {
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
            .recv(&msg.data[1..], &RecvMeta { message: msg }, env);

        self.process_result(res, env)
    }

    fn can_succeed(&self) -> bool {
        panic!("Assertion failed, Auth Layer instantiates EAP success")
    }
}

impl<I: AuthInnerLayer> AuthLayer<I> {
    pub fn new(candidates: Vec<I>) -> Self {
        assert!(!candidates.is_empty());
        AuthLayer {
            next_layer: candidates[0].clone(),
            candidates,
            peer_has_sent_nak: false,
        }
    }

    fn process_result(
        &mut self,
        res: AuthInnerLayerResult,
        env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        match res {
            AuthInnerLayerResult::Send(msg) => {
                let id = self.next_layer.method_identifier();
                let data = add_message_identifier_to_data(id, msg.data);
                ThisLayerResult::Send(MessageContent { data })
            }
            AuthInnerLayerResult::Finished => ThisLayerResult::Finished,
            AuthInnerLayerResult::Failed => ThisLayerResult::Failed,
            AuthInnerLayerResult::NextLayer => {
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

    use crate::DefaultEnvironment;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DummyProtocol {
        method_identifier: u8,
        events: Vec<AuthInnerLayerResult>,
    }

    impl DummyProtocol {
        fn new(method_identifier: u8, events: &[AuthInnerLayerResult]) -> Self {
            DummyProtocol {
                method_identifier,
                events: events.to_vec(),
            }
        }
    }

    impl AuthInnerLayer for DummyProtocol {
        fn method_identifier(&self) -> u8 {
            self.method_identifier
        }

        fn start(&mut self, _env: &mut dyn EapEnvironment) -> AuthInnerLayerResult {
            self.events.remove(0)
        }

        fn recv(
            &mut self,
            _msg: &[u8],
            _meta: &RecvMeta,
            _env: &mut dyn EapEnvironment,
        ) -> AuthInnerLayerResult {
            self.events.remove(0)
        }
    }

    #[test]
    fn auth_layer_is_auth() {
        let layer = AuthLayer::new(vec![DummyProtocol::new(1, &[])]);
        assert!(!layer.is_peer());
        assert!(layer.is_auth());
    }

    #[test]
    fn auth_layer_error_and_normal() {
        let mut env = DefaultEnvironment::new();
        let mut layer = AuthLayer::new(vec![
            DummyProtocol::new(
                1,
                &[
                    AuthInnerLayerResult::Send(MessageContent {
                        data: b"username?".to_vec(),
                    }),
                    AuthInnerLayerResult::NextLayer,
                ],
            ),
            DummyProtocol::new(
                2,
                &[
                    AuthInnerLayerResult::Send(MessageContent {
                        data: b"unsupported".to_vec(),
                    }),
                    AuthInnerLayerResult::Failed,
                ],
            ),
            DummyProtocol::new(
                4,
                &[
                    AuthInnerLayerResult::Send(MessageContent {
                        data: b"right".to_vec(),
                    }),
                    AuthInnerLayerResult::Finished,
                ],
            ),
            DummyProtocol::new(
                5,
                &[AuthInnerLayerResult::Send(MessageContent {
                    data: b"don't select me".to_vec(),
                })],
            ),
        ]);

        //  Auth inits conversation
        assert_eq!(
            layer.start(&mut env),
            ThisLayerResult::Send(MessageContent {
                data: b"\x01username?".to_vec()
            }),
        );

        {
            // Alternative Reality
            let mut layer = layer.clone();
            // Peer responds with unsupported method
            assert_eq!(
                layer.recv(
                    &Message::new(MessageCode::Response, 0, b"\x04wrong method"),
                    &mut env,
                ),
                ThisLayerResult::Failed,
            );
        }

        // Peer responds
        assert_eq!(
            layer.recv(
                &Message::new(MessageCode::Response, 0, b"\x01bob"),
                &mut env,
            ),
            ThisLayerResult::Send(MessageContent {
                data: b"\x02unsupported".to_vec()
            }),
        );

        {
            // Alternative Reality
            let mut layer = layer.clone();
            // Peer NAKs with unsupported method
            assert_eq!(
                layer.recv(
                    &Message::new(MessageCode::Response, 0, b"\x03\x07"),
                    &mut env,
                ),
                ThisLayerResult::Failed,
            );
        }

        // Peer sends NAK, wants to try method 5 or 4
        assert_eq!(
            layer.recv(
                &Message::new(MessageCode::Response, 0, b"\x03\x06\x05\x04"),
                &mut env,
            ),
            // We configured 4
            ThisLayerResult::Send(MessageContent {
                data: b"\x04right".to_vec()
            }),
        );

        {
            // Alternative Reality
            let mut layer = layer.clone();
            // Peers resends NAK (illegal)
            assert_eq!(
                layer.recv(
                    &Message::new(MessageCode::Response, 0, b"\x03\x04"),
                    &mut env,
                ),
                ThisLayerResult::Failed,
            );
        }

        // Peer responds
        assert_eq!(
            layer.recv(&Message::new(MessageCode::Response, 0, b"\x04"), &mut env,),
            ThisLayerResult::Finished,
        );
    }
}
