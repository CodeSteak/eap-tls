use crate::util::OwnedSlice;

use super::{EapEnvironment, ResponseBufferState};

#[cfg(feature = "std")]
pub type DefaultEnvironment = StdBoxEnvironment;

const DEFAULT_RESPONSE_BUFFER_SIZE: usize = 1020;

#[cfg(feature = "std")]
pub struct StdBoxEnvironment {
    name: Option<Vec<u8>>,
    response_buffer: Vec<u8>,
    response_buffer_state: ResponseBufferState,
}

#[cfg(feature = "std")]
impl Default for StdBoxEnvironment {
    fn default() -> Self {
        Self {
            name: None,
            response_buffer: vec![0; DEFAULT_RESPONSE_BUFFER_SIZE],
            response_buffer_state: ResponseBufferState::default(),
        }
    }
}

#[cfg(feature = "std")]
impl StdBoxEnvironment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_mtu(mtu: usize) -> Self {
        Self {
            response_buffer: vec![0; mtu],
            response_buffer_state: ResponseBufferState::default(),
            name: None,
        }
    }
}

#[cfg(feature = "std")]
impl EapEnvironment for StdBoxEnvironment {
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

pub struct StaticEnvironment<const N: usize = 1020> {
    name: Option<OwnedSlice<32>>,
    response_buffer: [u8; N],
    response_buffer_state: ResponseBufferState,
    random_function: fn(&mut [u8]),
}

impl<const N: usize> StaticEnvironment<N> {
    pub fn new(random_function: fn(&mut [u8])) -> Self {
        Self {
            name: None,
            response_buffer: [0; N],
            response_buffer_state: ResponseBufferState::default(),
            random_function,
        }
    }
}

impl<const N: usize> EapEnvironment for StaticEnvironment<N> {
    fn set_name(&mut self, name: &[u8]) {
        if let Ok(name) = name.try_into() {
            self.name = Some(name);
        }
    }

    fn name(&self) -> Option<&[u8]> {
        match &self.name {
            Some(name) => Some(name.as_ref()),
            None => None,
        }
    }

    fn fill_random(&self, buf: &mut [u8]) {
        (self.random_function)(buf)
    }

    fn response_buffer_state(&mut self) -> &mut ResponseBufferState {
        &mut self.response_buffer_state
    }

    fn response_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.response_buffer
    }

    fn response_buffer(&self) -> &[u8] {
        &self.response_buffer
    }
}
