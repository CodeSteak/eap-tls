use crate::{
    layers::mux::{TupleAppend, TupleById, TupleElement},
    message::{Message, MessageCode},
    EapEnvironment, MessageBuilder,
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
    pub message: Message<'a>,
}

pub trait AuthMethodLayer {
    fn method_identifier(&self) -> u8;
    fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> AuthMethodLayerResult<'a>;
    fn recv<'a>(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        env: &'a mut dyn EapEnvironment,
    ) -> AuthMethodLayerResult<'a>;
    fn selectable_by_nak(&self) -> bool {
        true
    }
}

pub enum AuthMethodLayerResult<'a> {
    Send(MessageBuilder<'a>),
    Finished(&'a mut dyn EapEnvironment),
    Failed(&'a mut dyn EapEnvironment),
    NextLayer(&'a mut dyn EapEnvironment),
}

impl<I> ThisLayer for AuthLayer<I>
where
    I: TupleById<dyn AuthMethodLayer>,
{
    fn is_peer(&self) -> bool {
        false
    }

    fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> ThisLayerResult<'a> {
        let res = self.current_layer().start(env);
        self.process_result(res)
    }

    fn recv<'a>(&mut self, msg: &Message, env: &'a mut dyn EapEnvironment) -> ThisLayerResult<'a> {
        if msg.code != MessageCode::Response {
            return ThisLayerResult::Failed(env);
        }

        if msg.body.is_empty() {
            // Message Too Short
            return ThisLayerResult::Failed(env);
        }

        let method_identifier = msg.body[0];
        if method_identifier == METHOD_CLIENT_PROPOSAL {
            if self.peer_has_sent_nak {
                // Protocol Violation
                return ThisLayerResult::Failed(env);
            }
            self.peer_has_sent_nak = true;

            for candidate in self.candidates.iter() {
                if candidate.selectable_by_nak()
                    && msg.body[1..].contains(&candidate.method_identifier())
                {
                    self.next_layer = candidate.method_identifier();

                    let res = self.current_layer().start(env);
                    return self.process_result(res);
                }
            }

            return ThisLayerResult::Failed(env); // <- no matching method
        }

        if method_identifier != self.next_layer {
            return ThisLayerResult::Failed(env);
        }

        let res = self
            .current_layer()
            .recv(&msg.body[1..], &RecvMeta { message: *msg }, env);

        self.process_result(res)
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
        P: TupleElement<Target = dyn AuthMethodLayer>,
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
    I: TupleById<dyn AuthMethodLayer>,
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

    fn current_layer(&mut self) -> &mut dyn AuthMethodLayer {
        // this is ensured by construction, see `new`
        self.candidates.get_by_id_mut(self.next_layer).unwrap()
    }

    fn process_result<'a>(
        &mut self, //
        res: AuthMethodLayerResult<'a>,
    ) -> ThisLayerResult<'a> {
        match res {
            AuthMethodLayerResult::Send(msg) => {
                let id = self.next_layer;

                ThisLayerResult::Send(msg.prepend(&[id]))
            }
            AuthMethodLayerResult::Finished(env) => ThisLayerResult::Finished(env),
            AuthMethodLayerResult::Failed(env) => ThisLayerResult::Failed(env),
            AuthMethodLayerResult::NextLayer(env) => {
                let current_idx = self.candidates.id_to_idx(self.next_layer).unwrap();
                self.next_layer = self
                    .candidates
                    .get_by_pos((current_idx + 1) % self.candidates.len())
                    .unwrap()
                    .method_identifier();

                if self.candidates.len() > 1 {
                    let res = self.current_layer().start(env);
                    self.process_result(res)
                } else {
                    ThisLayerResult::Failed(env) // <- Internal Issue
                }
            }
        }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use crate::{DefaultEnvironment, EapEnvironmentResponse, MessageBuilder};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum DummyEvent {
        Send(Vec<u8>),
        Finished,
        Failed,
        NextLayer,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DummyProtocol {
        method_identifier: u8,
        events: Vec<DummyEvent>,
    }

    impl DummyProtocol {
        fn new(method_identifier: u8, events: &[DummyEvent]) -> Self {
            DummyProtocol {
                method_identifier,
                events: events.to_vec(),
            }
        }
    }

    impl TupleElement for DummyProtocol {
        type Target = dyn AuthMethodLayer;

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

    impl AuthMethodLayer for DummyProtocol {
        fn method_identifier(&self) -> u8 {
            self.method_identifier
        }

        fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> AuthMethodLayerResult<'a> {
            match self.events.remove(0) {
                DummyEvent::Send(data) => AuthMethodLayerResult::Send(env.respond().write(&data)),
                DummyEvent::Finished => AuthMethodLayerResult::Finished(env),
                DummyEvent::Failed => AuthMethodLayerResult::Failed(env),
                DummyEvent::NextLayer => AuthMethodLayerResult::NextLayer(env),
            }
        }

        fn recv<'a>(
            &mut self,
            _msg: &[u8],
            _meta: &RecvMeta,
            env: &'a mut dyn EapEnvironment,
        ) -> AuthMethodLayerResult<'a> {
            self.start(env)
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
                    DummyEvent::Send(b"username?".to_vec()),
                    DummyEvent::NextLayer,
                ],
            ),
            DummyProtocol::new(
                2,
                &[
                    DummyEvent::Send(b"unsupported".to_vec()),
                    DummyEvent::Failed,
                ],
            ),
            DummyProtocol::new(
                4,
                &[DummyEvent::Send(b"right".to_vec()), DummyEvent::Finished],
            ),
            DummyProtocol::new(5, &[DummyEvent::Send(b"don't select me".to_vec())]),
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
