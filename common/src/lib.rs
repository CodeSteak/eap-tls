#![cfg_attr(not(feature = "std"), no_std)]

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

#[derive(Debug, Eq, PartialEq, Clone)]
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
