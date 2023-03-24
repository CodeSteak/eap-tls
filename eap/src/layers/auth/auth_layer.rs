use std::vec;

use crate::{
    layers::mux::{HasId, TupleAppend, TupleById},
    message::{Message, MessageCode, MessageContent},
    EapEnvironment, EapEnvironmentResponse,
};

use crate::layers::eap_layer::{
    PeerAuthLayer as ThisLayer, PeerAuthLayerResult as ThisLayerResult,
};

#[derive(Clone)]
pub struct AuthLayer<I> {
    peer_has_sent_nak: bool, // RFC allows only one NAK per session
    next_layer: u8,
    candidates: I,
}

pub const METHOD_CLIENT_PROPOSAL: u8 = 3;

pub struct RecvMeta<'a> {
    pub message: &'a Message,
}

pub trait AuthInnerLayer {
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

impl<I> ThisLayer for AuthLayer<I>
where
    I: TupleById<dyn AuthInnerLayer>,
{
    fn is_peer(&self) -> bool {
        false
    }

    fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> ThisLayerResult<'a> {
        let res = self.current_layer().start(env);
        self.process_result(res, env)
    }

    fn recv<'a>(&mut self, msg: &Message, env: &'a mut dyn EapEnvironment) -> ThisLayerResult<'a> {
        if msg.code != MessageCode::Response {
            return ThisLayerResult::Failed(env);
        }

        if msg.data.is_empty() {
            // Message Too Short
            return ThisLayerResult::Failed(env);
        }

        let method_identifier = msg.data[0];
        if method_identifier == METHOD_CLIENT_PROPOSAL {
            if self.peer_has_sent_nak {
                // Protocol Violation
                return ThisLayerResult::Failed(env);
            }
            self.peer_has_sent_nak = true;

            for candidate in self.candidates.iter() {
                if candidate.selectable_by_nak()
                    && msg.data[1..].contains(&candidate.method_identifier())
                {
                    self.next_layer = candidate.method_identifier();

                    let res = self.current_layer().start(env);
                    return self.process_result(res, env);
                }
            }

            return ThisLayerResult::Failed(env); // <- no matching method
        }

        if method_identifier != self.next_layer {
            return ThisLayerResult::Failed(env);
        }

        let res = self
            .current_layer()
            .recv(&msg.data[1..], &RecvMeta { message: msg }, env);

        self.process_result(res, env)
    }

    fn can_succeed(&mut self) -> bool {
        panic!("Assertion failed, Auth Layer instantiates EAP success")
    }
}

impl AuthLayer<()> {
    #[allow(unused)]
    pub fn new() -> Self {
        Self {
            peer_has_sent_nak: false,
            next_layer: 0,
            candidates: (),
        }
    }
}

impl<I> AuthLayer<I> {
    pub fn with<P>(self, candidate: P) -> AuthLayer<<I as TupleAppend<P>>::Output>
    where
        I: TupleAppend<P>,
        P: HasId<Target = dyn AuthInnerLayer>,
    {
        AuthLayer {
            peer_has_sent_nak: false,
            next_layer: if self.candidates.len() == 0 {
                candidate.id()
            } else {
                self.next_layer
            },
            candidates: self.candidates.append(candidate),
        }
    }
}

impl<I> AuthLayer<I>
where
    I: TupleById<dyn AuthInnerLayer>,
{
    #[allow(unused)]
    pub fn from_layers(candidates: I) -> Self {
        let next_layer = candidates.first().method_identifier();
        Self {
            next_layer,
            candidates,
            peer_has_sent_nak: false,
        }
    }

    fn current_layer(&mut self) -> &mut dyn AuthInnerLayer {
        // this is ensured by construction, see `new`
        self.candidates.get_by_id_mut(self.next_layer).unwrap()
    }

    fn process_result<'a>(
        &mut self,
        res: AuthInnerLayerResult,
        env: &'a mut dyn EapEnvironment,
    ) -> ThisLayerResult<'a> {
        match res {
            AuthInnerLayerResult::Send(msg) => {
                let id = self.next_layer;

                ThisLayerResult::Send(env.respond().write(&msg.data).prepend(&[id]))
            }
            AuthInnerLayerResult::Finished => ThisLayerResult::Finished(env),
            AuthInnerLayerResult::Failed => ThisLayerResult::Failed(env),
            AuthInnerLayerResult::NextLayer => {
                let current_idx = self.candidates.id_to_idx(self.next_layer).unwrap();
                self.next_layer = self
                    .candidates
                    .get_by_pos((current_idx + 1) % self.candidates.len())
                    .unwrap()
                    .method_identifier();

                if self.candidates.len() > 1 {
                    let res = self.current_layer().start(env);
                    self.process_result(res, env)
                } else {
                    ThisLayerResult::Failed(env) // <- Internal Issue
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

    use crate::{DefaultEnvironment, MessageBuilder};

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

    impl HasId for DummyProtocol {
        type Target = dyn AuthInnerLayer;

        fn id(&self) -> u8 {
            self.method_identifier
        }

        fn get(&self) -> &Self::Target {
            self
        }

        fn get_mut(&mut self) -> &mut Self::Target {
            self
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
        let layer = AuthLayer::from_layers((DummyProtocol::new(1, &[]),));
        assert!(!layer.is_peer());
        assert!(layer.is_auth());
    }

    #[test]
    fn auth_layer_error_and_normal() {
        let mut env = DefaultEnvironment::new();

        let mut layer = AuthLayer::from_layers((
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
        ));

        //  Auth inits conversation
        assert_eq!(
            layer.start(&mut env),
            ThisLayerResult::Send(MessageBuilder::from(b"\x01username?".as_slice()))
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
                ThisLayerResult::Failed(&mut DefaultEnvironment::new()),
            );
        }

        // Peer responds
        assert_eq!(
            layer.recv(
                &Message::new(MessageCode::Response, 0, b"\x01bob"),
                &mut env,
            ),
            ThisLayerResult::Send(MessageBuilder::from(b"\x02unsupported".as_slice())),
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
                ThisLayerResult::Failed(&mut DefaultEnvironment::new()),
            );
        }

        // Peer sends NAK, wants to try method 5 or 4
        assert_eq!(
            layer.recv(
                &Message::new(MessageCode::Response, 0, b"\x03\x06\x05\x04"),
                &mut env,
            ),
            // We configured 4
            ThisLayerResult::Send(MessageBuilder::from(b"\x04right".as_slice())),
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
                ThisLayerResult::Failed(&mut DefaultEnvironment::new()),
            );
        }

        // Peer responds
        assert_eq!(
            layer.recv(&Message::new(MessageCode::Response, 0, b"\x04"), &mut env,),
            ThisLayerResult::Finished(&mut DefaultEnvironment::new()),
        );
    }
}
