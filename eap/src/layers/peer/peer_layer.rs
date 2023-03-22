use crate::{
    layers::mux::{HasId, TupleAppend, TupleById},
    message::{Message, MessageContent},
    EapEnvironment,
};

use crate::layers::eap_layer::{InnerLayer as ThisLayer, InnerLayerOutput as ThisLayerResult};

//////
///
/// TODO: Missing Feature:
/// Make Server via EAP TLS a requirement for this

#[derive(Clone)]
pub struct PeerLayer<I> {
    next_layer: Option<u8>,
    candidates: I,
}

impl PeerLayer<()> {
    #[allow(unused)]
    pub fn new() -> Self {
        Self {
            next_layer: None,
            candidates: (),
        }
    }
}

impl<I> PeerLayer<I> {
    pub fn with<P>(self, candidate: P) -> PeerLayer<<I as TupleAppend<P>>::Output>
    where
        I: TupleAppend<P>,
        P: HasId<Target = dyn PeerInnerLayer>,
    {
        PeerLayer {
            next_layer: None,
            candidates: self.candidates.append(candidate),
        }
    }
}

pub struct RecvMeta<'a> {
    pub message: &'a Message,
}

pub trait PeerInnerLayer {
    /* */
    fn method_identifier(&self) -> u8;
    fn recv(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        env: &mut dyn EapEnvironment,
    ) -> PeerInnerLayerResult;

    fn selectable_by_nak(&self) -> bool {
        true
    }

    fn can_succeed(&self) -> Option<bool> {
        None
    }

    fn reset(&mut self) {}
}

pub const METHOD_CLIENT_PROPOSAL: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerInnerLayerResult {
    Noop,
    Send(MessageContent),
    Failed,
}

impl<I> ThisLayer for PeerLayer<I>
where
    I: TupleById<dyn PeerInnerLayer>,
{
    fn is_peer(&self) -> bool {
        true
    }

    fn can_succeed(&mut self) -> bool {
        for c in self.candidates.iter() {
            if Some(false) == c.can_succeed() {
                return false;
            }
        }

        true
    }

    fn start(&mut self, _env: &mut dyn EapEnvironment) -> ThisLayerResult {
        // NOP, Authenticator will send a Request
        ThisLayerResult::Noop
    }

    fn recv(&mut self, msg: &Message, env: &mut dyn EapEnvironment) -> ThisLayerResult {
        if msg.data.is_empty() {
            // Message Too Short
            return ThisLayerResult::Failed;
        }

        let method_identifier = msg.data[0];
        if Some(method_identifier) != self.next_layer {
            // Find a candidate
            match self.candidates.get_by_id_mut(method_identifier) {
                Some(c) => {
                    c.reset();
                    self.next_layer = Some(method_identifier);
                    let res = c.recv(&msg.data[1..], &RecvMeta { message: msg }, env);
                    self.process_result(res, env)
                }
                None => {
                    let mut data = vec![METHOD_CLIENT_PROPOSAL];
                    for c in self.candidates.iter() {
                        if c.selectable_by_nak() {
                            data.push(c.method_identifier());
                        }
                    }

                    ThisLayerResult::Send(MessageContent { data })
                }
            }
        } else {
            match self.candidates.get_by_id_mut(method_identifier) {
                Some(c) => {
                    let res = c.recv(&msg.data[1..], &RecvMeta { message: msg }, env);
                    self.process_result(res, env)
                }
                None => {
                    unreachable!()
                }
            }
        }
    }

    fn is_auth(&self) -> bool {
        !self.is_peer()
    }

    fn step(
        &mut self,
        input: crate::layers::eap_layer::InnerLayerInput,
        env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        match input {
            crate::layers::eap_layer::InnerLayerInput::Start => self.start(env),
            crate::layers::eap_layer::InnerLayerInput::Recv(msg) => self.recv(&msg, env),
        }
    }
}

impl<I> PeerLayer<I> {
    fn process_result(
        &mut self,
        res: PeerInnerLayerResult,
        _env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        match res {
            PeerInnerLayerResult::Noop => ThisLayerResult::Noop,
            PeerInnerLayerResult::Send(data) => {
                let data = vec![self.next_layer.unwrap()]
                    .into_iter()
                    .chain(data.data.into_iter())
                    .collect();
                ThisLayerResult::Send(MessageContent { data })
            }
            PeerInnerLayerResult::Failed => ThisLayerResult::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{message::MessageCode, DefaultEnvironment};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DummyProtocol {
        method_identifier: u8,
        events: Vec<PeerInnerLayerResult>,
    }

    impl PeerInnerLayer for DummyProtocol {
        fn method_identifier(&self) -> u8 {
            self.method_identifier
        }

        fn recv(
            &mut self,
            _msg: &[u8],
            _meta: &RecvMeta,
            _env: &mut dyn EapEnvironment,
        ) -> PeerInnerLayerResult {
            self.events.remove(0)
        }

        fn selectable_by_nak(&self) -> bool {
            self.method_identifier != 1
        }
    }

    impl HasId for DummyProtocol {
        type Target = dyn PeerInnerLayer;
        fn id(&self) -> u8 {
            self.method_identifier()
        }

        fn get(&self) -> &Self::Target {
            self
        }

        fn get_mut(&mut self) -> &mut Self::Target {
            self
        }
    }

    #[test]
    fn peer_is_peer() {
        let layer = PeerLayer::new().with(DummyProtocol {
            method_identifier: 1,
            events: vec![],
        });
        assert!(layer.is_peer());
        assert!(!layer.is_auth());
    }

    #[test]
    fn conversation() {
        let mut env = DefaultEnvironment::new();
        let mut layer = PeerLayer::new()
            .with(DummyProtocol {
                method_identifier: 1,
                events: vec![
                    PeerInnerLayerResult::Send(MessageContent {
                        data: b"Bob".to_vec(),
                    }),
                    PeerInnerLayerResult::Failed,
                ],
            })
            .with(DummyProtocol {
                method_identifier: 4,
                events: vec![PeerInnerLayerResult::Send(MessageContent {
                    data: b"Ok".to_vec(),
                })],
            })
            .with(DummyProtocol {
                method_identifier: 2,
                events: vec![PeerInnerLayerResult::Failed],
            });

        assert_eq!(layer.start(&mut env), ThisLayerResult::Noop);

        // Send a Request
        assert_eq!(
            layer.recv(&Message::new(MessageCode::Request, 0, b"\x01"), &mut env),
            ThisLayerResult::Send(MessageContent {
                data: b"\x01Bob".to_vec()
            })
        );

        // Protocol 1 has finished,
        // request non existent protocol 6
        assert_eq!(
            layer.recv(&Message::new(MessageCode::Request, 0, b"\x06"), &mut env),
            ThisLayerResult::Send(MessageContent {
                data: b"\x03\x04\x02".to_vec()
            })
        );

        // Alternative Reality
        {
            let mut layer = layer.clone();
            // Request protocol 2
            assert_eq!(
                layer.recv(&Message::new(MessageCode::Request, 0, b"\x02"), &mut env),
                ThisLayerResult::Failed
            );
        }

        // Request protocol 3
        assert_eq!(
            layer.recv(&Message::new(MessageCode::Request, 0, b"\x04"), &mut env),
            ThisLayerResult::Send(MessageContent {
                data: b"\x04Ok".to_vec(),
            })
        );
    }
}
