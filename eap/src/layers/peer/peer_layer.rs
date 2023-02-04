use crate::{
    message::{Message, MessageCode, MessageContent},
    EapEnvironment,
};

use crate::layers::eap_layer::{InnerLayer as ThisLayer, InnerLayerOutput as ThisLayerResult};

pub struct PeerLayer<I: InnerLayer> {
    state: State,
    next_layer: Option<I>,
    candidates: Vec<I>, // <- should be okay for now
}

enum State {
    Default {},
    Finished {},
    Failed {},
}
pub enum PeerResult {
    Ok,
}

pub struct RecvMeta<'a> {
    pub message: &'a Message,
}

pub trait InnerLayer: Clone {
    /* */
    fn method_identifier(&self) -> u8;
    fn start(&mut self, env: &mut dyn EapEnvironment) -> InnerResult;
    fn recv(&mut self, msg: &[u8], meta: &RecvMeta, env: &mut dyn EapEnvironment) -> InnerResult;
}

pub const METHOD_CLIENT_PROPOSAL: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerResult {
    Noop,
    Send(MessageContent),
    Failed,
}

impl<I: InnerLayer> ThisLayer for PeerLayer<I> {
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

    fn recv(&mut self, msg: Message, env: &mut dyn EapEnvironment) -> ThisLayerResult {
        match msg.code {
            MessageCode::Request => { /* Expected */ }
            MessageCode::Response => {
                // Unexpected
                return ThisLayerResult::Failed;
            }
            MessageCode::Success => {
                self.state = State::Finished {};
                return ThisLayerResult::Finished;
            }
            MessageCode::Failure => {
                self.state = State::Failed {};
                return ThisLayerResult::Failed;
            }
        }

        match self.state {
            State::Default {} => { /* NOP */ }
            State::Finished {} => {
                return ThisLayerResult::Finished;
            }
            State::Failed {} => {
                return ThisLayerResult::Failed;
            }
        }

        if msg.data.len() < 1 {
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

                    let res = c.recv(&msg.data[1..], &RecvMeta { message: &msg }, env);
                    return self.process_result(res, env);
                }
            }

            // No candidate found
            // Send NAK.

            let mut data = vec![METHOD_CLIENT_PROPOSAL];
            for c in self.candidates.iter_mut() {
                data.push(c.method_identifier());
            }

            return ThisLayerResult::Send(MessageContent { data });
        } else {
            // Found a candidate
            let res = self.next_layer.as_mut().unwrap().recv(
                &msg.data[1..],
                &RecvMeta { message: &msg },
                env,
            );
            return self.process_result(res, env);
        }
    }
}

impl<I: InnerLayer> PeerLayer<I> {
    fn process_result(
        &mut self,
        res: InnerResult,
        env: &mut dyn EapEnvironment,
    ) -> ThisLayerResult {
        match res {
            InnerResult::Noop => ThisLayerResult::Noop,
            InnerResult::Send(data) => {
                let data = vec![self.next_layer.as_ref().unwrap().method_identifier()]
                    .into_iter()
                    .chain(data.data.into_iter())
                    .collect();
                ThisLayerResult::Send(MessageContent { data })
            }
            InnerResult::Failed => ThisLayerResult::Failed,
        }
    }
}
