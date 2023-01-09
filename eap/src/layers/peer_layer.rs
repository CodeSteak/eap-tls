use crate::{message::Message, EapEnvironment};

pub struct PeerLayer {
    state: State,
}

enum State {
    Default {},
    Finished {},
    Failed {},
}
pub enum PeerResult {
    Ok,
}

impl PeerLayer {
    pub fn recv(&mut self, msg: Message, env: &mut dyn EapEnvironment) -> PeerResult {
        unimplemented!();
    }
}
