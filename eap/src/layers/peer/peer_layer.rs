use crate::{
    layers::mux::{HasId, TupleAppend, TupleById},
    message::{Message, MessageContent},
    EapEnvironment, EapEnvironmentResponse,
};

use crate::layers::eap_layer::{PeerAuthLayer, PeerAuthLayerResult};

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
        P: HasId<Target = dyn PeerMethodLayer>,
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

pub trait PeerMethodLayer {
    /* */
    fn method_identifier(&self) -> u8;
    fn recv(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        env: &mut dyn EapEnvironment,
    ) -> PeerMethodLayerResult;

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
pub enum PeerMethodLayerResult {
    Noop,
    Send(MessageContent),
    Failed,
}

impl<I> PeerAuthLayer for PeerLayer<I>
where
    I: TupleById<dyn PeerMethodLayer>,
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

    fn start<'a>(&mut self, env: &'a mut dyn EapEnvironment) -> PeerAuthLayerResult<'a> {
        // NOP, Authenticator will send a Request
        PeerAuthLayerResult::Noop(env)
    }

    fn recv<'a>(
        &mut self,
        msg: &Message,
        env: &'a mut dyn EapEnvironment,
    ) -> PeerAuthLayerResult<'a> {
        if msg.data.is_empty() {
            // Message Too Short
            return PeerAuthLayerResult::Failed(env);
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

                    PeerAuthLayerResult::Send(env.respond().write(&data))
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

    fn step<'a>(
        &mut self,
        input: crate::layers::eap_layer::PeerAuthLayerInput,
        env: &'a mut dyn EapEnvironment,
    ) -> PeerAuthLayerResult<'a> {
        match input {
            crate::layers::eap_layer::PeerAuthLayerInput::Start => self.start(env),
            crate::layers::eap_layer::PeerAuthLayerInput::Recv(msg) => self.recv(&msg, env),
        }
    }
}

impl<I> PeerLayer<I> {
    fn process_result<'a>(
        &mut self,
        res: PeerMethodLayerResult,
        env: &'a mut dyn EapEnvironment,
    ) -> PeerAuthLayerResult<'a> {
        match res {
            PeerMethodLayerResult::Noop => PeerAuthLayerResult::Noop(env),
            PeerMethodLayerResult::Send(data) => PeerAuthLayerResult::Send(
                env.respond()
                    .write(&data.data)
                    .prepend(&[self.next_layer.unwrap()]),
            ),
            PeerMethodLayerResult::Failed => PeerAuthLayerResult::Failed(env),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{message::MessageCode, DefaultEnvironment, MessageBuilder};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DummyProtocol {
        method_identifier: u8,
        events: Vec<PeerMethodLayerResult>,
    }

    impl PeerMethodLayer for DummyProtocol {
        fn method_identifier(&self) -> u8 {
            self.method_identifier
        }

        fn recv(
            &mut self,
            _msg: &[u8],
            _meta: &RecvMeta,
            _env: &mut dyn EapEnvironment,
        ) -> PeerMethodLayerResult {
            self.events.remove(0)
        }

        fn selectable_by_nak(&self) -> bool {
            self.method_identifier != 1
        }
    }

    impl HasId for DummyProtocol {
        type Target = dyn PeerMethodLayer;
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
                    PeerMethodLayerResult::Send(MessageContent {
                        data: b"Bob".to_vec(),
                    }),
                    PeerMethodLayerResult::Failed,
                ],
            })
            .with(DummyProtocol {
                method_identifier: 4,
                events: vec![PeerMethodLayerResult::Send(MessageContent {
                    data: b"Ok".to_vec(),
                })],
            })
            .with(DummyProtocol {
                method_identifier: 2,
                events: vec![PeerMethodLayerResult::Failed],
            });

        assert_eq!(
            layer.start(&mut env),
            PeerAuthLayerResult::Noop(&mut DefaultEnvironment::new())
        );

        // Send a Request
        assert_eq!(
            layer.recv(&Message::new(MessageCode::Request, 0, b"\x01"), &mut env),
            PeerAuthLayerResult::Send(MessageBuilder::from(b"\x01Bob".as_slice()))
        );

        // Protocol 1 has finished,
        // request non existent protocol 6
        assert_eq!(
            layer.recv(&Message::new(MessageCode::Request, 0, b"\x06"), &mut env),
            PeerAuthLayerResult::Send(MessageBuilder::from(b"\x03\x04\x02".as_slice()))
        );

        // Alternative Reality
        {
            let mut layer = layer.clone();
            // Request protocol 2
            assert_eq!(
                layer.recv(&Message::new(MessageCode::Request, 0, b"\x02"), &mut env),
                PeerAuthLayerResult::Failed(&mut DefaultEnvironment::new())
            );
        }

        // Request protocol 3
        assert_eq!(
            layer.recv(&Message::new(MessageCode::Request, 0, b"\x04"), &mut env),
            PeerAuthLayerResult::Send(MessageBuilder::from(b"\x04Ok".as_slice()))
        );
    }
}
