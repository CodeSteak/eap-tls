use super::{EapEnvironment, ResponseBufferState};

pub type DefaultEnvironment = StdBoxEnvironment<1020>;

pub struct StdBoxEnvironment<const N: usize = 1020> {
    name: Option<Vec<u8>>,
    response_buffer: Box<[u8; N]>,
    response_buffer_state: ResponseBufferState,
}

impl<const N: usize> Default for StdBoxEnvironment<N> {
    fn default() -> Self {
        Self {
            name: None,
            response_buffer: Box::new([0; N]),
            response_buffer_state: ResponseBufferState::default(),
        }
    }
}

impl<const N: usize> StdBoxEnvironment<N> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<const N: usize> EapEnvironment for StdBoxEnvironment<N> {
    fn set_name(&mut self, name: &[u8]) {
        self.name = Some(name.to_vec());
    }

    fn name(&self) -> Option<&[u8]> {
        self.name.as_deref()
    }

    fn fill_random(&self, buf: &mut [u8]) {
        getrandom::getrandom(buf).unwrap();
    }

    fn response_buffer_state(&mut self) -> &mut ResponseBufferState {
        &mut self.response_buffer_state
    }

    fn response_buffer_mut(&mut self) -> &mut [u8] {
        &mut *self.response_buffer
    }

    fn response_buffer(&self) -> &[u8] {
        &*self.response_buffer
    }
}
