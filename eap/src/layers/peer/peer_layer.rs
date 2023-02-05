use crate::{
    message::{Message, MessageContent},
    EapEnvironment,
};

use crate::layers::eap_layer::{InnerLayer as ThisLayer, InnerLayerOutput as ThisLayerResult};

//////
///
/// TODO: Missing Feature:
/// Make Server via EAP TLS a requirement for this

#[derive(Clone)]
pub struct PeerLayer<I: PeerInnerLayer> {
    next_layer: Option<I>,
    candidates: Vec<I>, // <- should be okay for now
}

impl<I: PeerInnerLayer> PeerLayer<I> {
    #[allow(unused)]
    pub fn new(candidates: Vec<I>) -> Self {
        Self {
            next_layer: None,
            candidates,
        }
    }
}

pub struct RecvMeta<'a> {
    pub message: &'a Message,
}

pub trait PeerInnerLayer: Clone {
    /* */
    fn method_identifier(&self) -> u8;
    fn start(&mut self, env: &mut dyn EapEnvironment) -> PeerInnerLayerResult;
    fn recv(
        &mut self,
        msg: &[u8],
        meta: &RecvMeta,
        env: &mut dyn EapEnvironment,
    ) -> PeerInnerLayerResult;
    fn selectable_by_nak(&self) -> bool {
        true
    }
}

pub const METHOD_CLIENT_PROPOSAL: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerInnerLayerResult {
    Noop,
    Send(MessageContent),
    Failed,
}

impl<I: PeerInnerLayer> ThisLayer for PeerLayer<I> {
    fn is_peer(&self) -> bool {
        true
    }

    fn can_succeed(&self) -> bool {
        unimplemented!();
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
        if Some(method_identifier)
            != self
                .next_layer
                .as_ref()
                .map(|layer| layer.method_identifier())
        {
            // Find a candidate
            for c in self.candidates.iter_mut() {
                if c.method_identifier() == method_identifier {
                    self.next_layer = Some(c.clone());

                    let res = c.recv(&msg.data[1..], &RecvMeta { message: msg }, env);
                    return self.process_result(res, env);
                }
            }

            // No candidate found
            // Send NAK.

            let mut data = vec![METHOD_CLIENT_PROPOSAL];
            for c in self.candidates.iter_mut() {
                if c.selectable_by_nak() {
                    data.push(c.method_identifier());
                }
            }

            ThisLayerResult::Send(MessageContent { data })
        } else {
            // Found a candidate
            let res = self.next_layer.as_mut().unwrap().recv(
                &msg.data[1..],
                &RecvMeta { message: msg },
                env,
            );
            self.process_result(res, env)
        }
    }
}

impl<I: PeerInnerLayer> PeerLayer<I> {
    fn process_result(
        &mut self,
        res: PeerInnerLayerResult,
        _env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        match res {
            PeerInnerLayerResult::Noop => ThisLayerResult::Noop,
            PeerInnerLayerResult::Send(data) => {
                let data = vec![self.next_layer.as_ref().unwrap().method_identifier()]
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

        fn start(&mut self, _env: &mut dyn EapEnvironment) -> PeerInnerLayerResult {
            self.events.remove(0)
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

    #[test]
    fn peer_is_peer() {
        let layer = PeerLayer::new(vec![DummyProtocol {
            method_identifier: 1,
            events: vec![],
        }]);
        assert!(layer.is_peer());
        assert!(!layer.is_auth());
    }

    #[test]
    fn conversation() {
        let mut env = DefaultEnvironment::new();
        let mut layer = PeerLayer::new(vec![
            DummyProtocol {
                method_identifier: 1,
                events: vec![
                    PeerInnerLayerResult::Send(MessageContent {
                        data: b"Bob".to_vec(),
                    }),
                    PeerInnerLayerResult::Failed,
                ],
            },
            DummyProtocol {
                method_identifier: 4,
                events: vec![PeerInnerLayerResult::Send(MessageContent {
                    data: b"Ok".to_vec(),
                })],
            },
            DummyProtocol {
                method_identifier: 2,
                events: vec![PeerInnerLayerResult::Failed],
            },
        ]);

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
