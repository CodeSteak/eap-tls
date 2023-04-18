mod authenticator;
use core::borrow::Borrow;

pub use authenticator::*;

mod peer;
pub use peer::*;

pub trait EapWrapper {
    fn receive(&mut self, msg: &[u8]);
    fn step(&mut self) -> EapStepResult<'_>;
}

pub struct EapStepResult<'a> {
    pub status: EapStepStatus,
    pub response: Option<&'a [u8]>,
}

impl EapStepResult<'_> {
    pub fn into_owned(self) -> OwnedEapStepResult {
        OwnedEapStepResult {
            status: self.status,
            response: self.response.map(|x| x.to_vec()),
        }
    }
}

pub struct OwnedEapStepResult {
    pub status: EapStepStatus,
    pub response: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum EapStepStatus {
    Ok,
    Error,
    Finished,
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use crate::layers::{auth::AuthMethodLayer, mux::TupleById, peer::peer_layer::PeerMethodLayer};

    use super::*;

    fn run<I, O>(
        peer: &mut Peer<I>,
        auth: &mut Authenticator<O>,
        package_drop_rate: Option<(f32, u64)>,
    ) -> (PeerStepStatus, AuthenticatorStepStatus)
    where
        I: TupleById<dyn PeerMethodLayer>,
        O: TupleById<dyn AuthMethodLayer>,
    {
        let (package_drop_rate, seed) = package_drop_rate.unwrap_or((0.0, 0));
        let mut rng = StdRng::seed_from_u64(package_drop_rate.to_bits() as u64 ^ 0xdeadbeef ^ seed);

        for _ in 0..1000 {
            let EapStepResult {
                status: peer_status,
                response: peer_response,
            } = peer.step();
            let peer_response = peer_response.map(|m| m.to_vec());

            if let Some(response) = peer_response {
                if rng.gen::<f32>() > package_drop_rate {
                    auth.receive(&response);
                }
            }

            let EapStepResult {
                status: auth_status,
                response: auth_response,
            } = auth.step();
            let auth_response = auth_response.map(|m| m.to_vec());

            if let Some(response) = auth_response {
                if rng.gen::<f32>() > package_drop_rate {
                    peer.receive(&response);
                }
            }

            if peer_status != PeerStepStatus::Ok && auth_status != AuthenticatorStepStatus::Ok {
                return (peer_status, auth_status);
            }
        }

        panic!("Too many iterations");
    }

    #[test]
    fn test_wrapper_success() {
        let mut peer = Peer::new_password("testuser", "pasword123");
        let mut auth = Authenticator::new_password("pasword123");

        let (peer_res, auth_res) = run(&mut peer, &mut auth, None);

        assert_eq!(peer_res, PeerStepStatus::Finished);
        assert_eq!(auth_res, AuthenticatorStepStatus::Finished);
    }

    #[test]
    fn test_wrapper_fail() {
        let mut peer = Peer::new_password("testuser", "i forgot my password");
        let mut auth = Authenticator::new_password("pasword123");

        let (peer_res, auth_res) = run(&mut peer, &mut auth, None);

        assert_eq!(peer_res, PeerStepStatus::Error);
        assert_eq!(auth_res, AuthenticatorStepStatus::Error);
    }

    #[test]
    fn test_wrapper_package_loss() {
        let mut peer = Peer::new_password("testuser", "pasword123");
        let mut auth = Authenticator::new_password("pasword123");

        let (peer_res, auth_res) = run(&mut peer, &mut auth, Some((0.5, 4808468)));

        assert_eq!(peer_res, PeerStepStatus::Finished);
        assert_eq!(auth_res, AuthenticatorStepStatus::Finished);
    }

    #[test]
    fn test_success_rate_on_losses() {
        let mut success = 0;
        let tries = 100;

        for i in 0..tries {
            let mut peer = Peer::new_password("testuser", "pasword123");
            let mut auth = Authenticator::new_password("pasword123");

            let (peer_res, auth_res) = run(&mut peer, &mut auth, Some((0.5, i)));

            match (peer_res, auth_res) {
                (PeerStepStatus::Finished, AuthenticatorStepStatus::Finished) => success += 1,
                (PeerStepStatus::Error, AuthenticatorStepStatus::Error) => {}
                (PeerStepStatus::Error, AuthenticatorStepStatus::Finished) => {
                    // Success packet was lost
                }
                _ => {
                    panic!("Unexpected result: ({peer_res:?}, {auth_res:?})");
                }
            }
        }

        dbg!(success, tries);

        assert!(success as f32 > tries as f32 * 0.25);
    }

    #[test]
    fn test_timeout() {
        let mut peer = Peer::new_password("testuser", "pasword123");
        let mut auth = Authenticator::new_password("pasword123");

        let (peer_res, auth_res) = run(&mut peer, &mut auth, Some((0.9, 6211651))); // Drop ~ all packages

        assert_eq!(peer_res, PeerStepStatus::Error);
        assert_eq!(auth_res, AuthenticatorStepStatus::Error);
    }
}
