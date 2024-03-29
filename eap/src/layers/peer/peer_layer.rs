use crate::{
    layers::mux::{TupleAppend, TupleById, TupleElement},
    message::Message,
    EapEnvironment, EapEnvironmentResponse, MessageBuilder,
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
        P: TupleElement<Target = dyn PeerMethodLayer>,
    {
        PeerLayer {
            next_layer: None,
            candidates: self.candidates.append(candidate),
        }
    }
}

pub struct RecvMeta<'a> {
    pub message: Message<'a>,
}

pub trait PeerMethodLayer {
    /* */
    fn method_identifier(&self) -> u8;
    fn recv<'a>(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        env: &'a mut dyn EapEnvironment,
    ) -> PeerMethodLayerResult<'a>;

    fn selectable_by_nak(&self) -> bool {
        true
    }

    fn can_succeed(&self) -> Option<bool> {
        None
    }

    fn reset(&mut self) {}
}

pub const METHOD_CLIENT_PROPOSAL: u8 = 3;

pub enum PeerMethodLayerResult<'a> {
    Noop(&'a mut dyn EapEnvironment),
    Send(MessageBuilder<'a>),
    Failed(&'a mut dyn EapEnvironment),
}

impl<'a> PartialEq for PeerMethodLayerResult<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PeerMethodLayerResult::Noop(_), PeerMethodLayerResult::Noop(_)) => true,
            (PeerMethodLayerResult::Send(a), PeerMethodLayerResult::Send(b)) => {
                a.slice() == b.slice()
            }
            (PeerMethodLayerResult::Failed(_), PeerMethodLayerResult::Failed(_)) => true,
            _ => false,
        }
    }
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
            if let Some(val) = c.can_succeed() {
                return val;
            }
        }

        false
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
        if msg.body.is_empty() {
            // Message Too Short
            return PeerAuthLayerResult::Failed(env);
        }

        let method_identifier = msg.body[0];
        if Some(method_identifier) != self.next_layer {
            // Find a candidate
            match self.candidates.get_by_id_mut(method_identifier) {
                Some(c) => {
                    c.reset();
                    self.next_layer = Some(method_identifier);
                    let res = c.recv(&msg.body[1..], &RecvMeta { message: *msg }, env);
                    self.process_result(res)
                }
                None => {
                    let mut message_builder = env.respond();
                    message_builder = message_builder.write(&[METHOD_CLIENT_PROPOSAL]);

                    for c in self.candidates.iter() {
                        if c.selectable_by_nak() {
                            message_builder = message_builder.write(&[c.method_identifier()]);
                        }
                    }

                    PeerAuthLayerResult::Send(message_builder)
                }
            }
        } else {
            match self.candidates.get_by_id_mut(method_identifier) {
                Some(c) => {
                    let res = c.recv(&msg.body[1..], &RecvMeta { message: *msg }, env);
                    self.process_result(res)
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
    fn process_result<'a>(&mut self, res: PeerMethodLayerResult<'a>) -> PeerAuthLayerResult<'a> {
        match res {
            PeerMethodLayerResult::Noop(env) => PeerAuthLayerResult::Noop(env),
            PeerMethodLayerResult::Send(data) => {
                PeerAuthLayerResult::Send(data.prepend(&[self.next_layer.unwrap()]))
            }
            PeerMethodLayerResult::Failed(env) => PeerAuthLayerResult::Failed(env),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use crate::{message::MessageCode, DefaultEnvironment, MessageBuilder};

    use super::*;

    #[derive(Clone)]
    enum DummyEvent {
        #[allow(dead_code)]
        Noop,
        Send(Vec<u8>),
        Failed,
    }

    #[derive(Clone)]
    struct DummyProtocol {
        method_identifier: u8,
        events: Vec<DummyEvent>,
    }

    impl PeerMethodLayer for DummyProtocol {
        fn method_identifier(&self) -> u8 {
            self.method_identifier
        }

        fn recv<'a>(
            &mut self,
            _msg: &[u8],
            _meta: &RecvMeta,
            env: &'a mut dyn EapEnvironment,
        ) -> PeerMethodLayerResult<'a> {
            match self.events.remove(0) {
                DummyEvent::Noop => PeerMethodLayerResult::Noop(env),
                DummyEvent::Send(data) => PeerMethodLayerResult::Send(env.respond().write(&data)),
                DummyEvent::Failed => PeerMethodLayerResult::Failed(env),
            }
        }

        fn selectable_by_nak(&self) -> bool {
            self.method_identifier != 1
        }
    }

    impl TupleElement for DummyProtocol {
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
    fn test_switching() {
        let mut env = DefaultEnvironment::new();

        let mut layer = PeerLayer::new()
            .with(DummyProtocol {
                method_identifier: 1,
                events: vec![DummyEvent::Send(b"Bob".to_vec()), DummyEvent::Failed],
            })
            .with(DummyProtocol {
                method_identifier: 4,
                events: vec![DummyEvent::Send(b"Ok".to_vec())],
            })
            .with(DummyProtocol {
                method_identifier: 2,
                events: vec![DummyEvent::Failed],
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
