mod authenticator;
pub use authenticator::*;

mod peer;
pub use peer::*;

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use crate::layers::{auth::AuthInnerLayer, mux::TupleById, peer::peer_layer::PeerInnerLayer};

    use super::*;

    fn run<I, O>(
        peer: &mut Peer<I>,
        auth: &mut Authenticator<O>,
        package_drop_rate: Option<(f32, u64)>,
    ) -> (PeerStepStatus, AuthenticatorStepStatus)
    where
        I: TupleById<dyn PeerInnerLayer>,
        O: TupleById<dyn AuthInnerLayer>,
    {
        let (package_drop_rate, seed) = package_drop_rate.unwrap_or((0.0, 0));
        let mut rng = StdRng::seed_from_u64(package_drop_rate.to_bits() as u64 ^ 0xdeadbeef ^ seed);

        for _ in 0..1000 {
            let peer_res = peer.step();

            if let Some(response) = peer_res.response {
                if rng.gen::<f32>() > package_drop_rate {
                    auth.receive(&response);
                }
            }

            let auth_res = auth.step();

            if let Some(response) = auth_res.response {
                if rng.gen::<f32>() > package_drop_rate {
                    peer.receive(&response);
                }
            }

            if peer_res.status != PeerStepStatus::Ok
                && auth_res.status != AuthenticatorStepStatus::Ok
            {
                return (peer_res.status, auth_res.status);
            }
        }

        panic!("Too many iterations");
    }

    #[test]
    fn test_wrapper_success() {
        let mut peer = Peer::new("testuser", "pasword123");
        let mut auth = Authenticator::new("pasword123");

        let (peer_res, auth_res) = run(&mut peer, &mut auth, None);

        assert_eq!(peer_res, PeerStepStatus::Finished);
        assert_eq!(auth_res, AuthenticatorStepStatus::Finished);
    }

    #[test]
    fn test_wrapper_fail() {
        let mut peer = Peer::new("testuser", "i forgot my password");
        let mut auth = Authenticator::new("pasword123");

        let (peer_res, auth_res) = run(&mut peer, &mut auth, None);

        assert_eq!(peer_res, PeerStepStatus::Error);
        assert_eq!(auth_res, AuthenticatorStepStatus::Error);
    }

    #[test]
    fn test_wrapper_package_loss() {
        let mut peer = Peer::new("testuser", "pasword123");
        let mut auth = Authenticator::new("pasword123");

        let (peer_res, auth_res) = run(&mut peer, &mut auth, Some((0.5, 4808468)));

        assert_eq!(peer_res, PeerStepStatus::Finished);
        assert_eq!(auth_res, AuthenticatorStepStatus::Finished);
    }

    #[test]
    fn test_success_rate_on_losses() {
        let mut success = 0;
        let tries = 100;

        for i in 0..tries {
            let mut peer = Peer::new("testuser", "pasword123");
            let mut auth = Authenticator::new("pasword123");

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
        let mut peer = Peer::new("testuser", "pasword123");
        let mut auth = Authenticator::new("pasword123");

        let (peer_res, auth_res) = run(&mut peer, &mut auth, Some((0.9, 6211651))); // Drop ~ all packages

        assert_eq!(peer_res, PeerStepStatus::Error);
        assert_eq!(auth_res, AuthenticatorStepStatus::Error);
    }
}
