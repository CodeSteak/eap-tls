#[cfg(feature = "std")]
pub mod default_env;
#[cfg(feature = "std")]
pub use default_env::*;

use crate::message::MessageCode;
pub trait EapEnvironment {
    fn set_name(&mut self, name: &[u8]); // <- Extract Somehow

    fn name(&self) -> Option<&[u8]>; // <- Extract Somehow, make generic for Peer/Auth

    fn max_invalid_message_count(&self) -> u16 {
        10 // Some default value
    }

    fn max_retransmit_count(&self) -> u16 {
        4 // 3~5 Suggested by RFC
    }

    fn max_timeout_count(&self) -> u16 {
        10 // Some default value
    }

    fn fill_random(&self, buf: &mut [u8]);

    fn response_buffer_state(&mut self) -> &mut ResponseBufferState;
    fn response_buffer_mut(&mut self) -> &mut [u8];
    fn response_buffer(&self) -> &[u8];
}

#[derive(Default)]
pub enum ResponseBufferState {
    #[default]
    Dirty,
    Message {
        offset: usize,
        length: usize,
    },
}

pub trait EapEnvironmentResponse<'a>: Sized {
    fn respond(self) -> MessageBuilder<'a>;
    fn last_message(self) -> Result<ResponseMessage<'a>, Self>;

    fn respond_with(
        self,
        code: MessageCode,
        identifier: u8,
        content: &[u8],
    ) -> ResponseMessage<'a> {
        self.respond().write(content).build(code, identifier)
    }
}

impl<'a> EapEnvironmentResponse<'a> for &'a mut dyn EapEnvironment {
    fn respond(self) -> MessageBuilder<'a> {
        *self.response_buffer_state() = ResponseBufferState::Dirty;
        MessageBuilder {
            env: EnvOrOwned::Env(self),
            offset: 5,
            length: 0,
        }
    }

    fn last_message(self) -> Result<ResponseMessage<'a>, Self> {
        match self.response_buffer_state() {
            ResponseBufferState::Message { offset, length } => {
                let offset = *offset;
                let length = *length;

                let builder = MessageBuilder {
                    env: EnvOrOwned::Env(self),
                    offset,
                    length,
                };
                Ok(ResponseMessage(builder))
            }
            _ => Err(self),
        }
    }
}

pub struct MessageBuilder<'a> {
    env: EnvOrOwned<'a>,
    length: usize,
    offset: usize,
}

pub enum EnvOrOwned<'a> {
    Env(&'a mut dyn EapEnvironment),
    #[cfg(test)] // This is needed to make tests more ergonomic
    Owned {
        buffer: Vec<u8>,
        state: ResponseBufferState,
    },
}

impl<'a> MessageBuilder<'a> {
    pub fn response_buffer(&self) -> &[u8] {
        match &self.env {
            EnvOrOwned::Env(env) => env.response_buffer(),
            #[cfg(test)]
            EnvOrOwned::Owned { buffer, .. } => buffer,
        }
    }

    pub fn response_buffer_mut(&mut self) -> &mut [u8] {
        match &mut self.env {
            EnvOrOwned::Env(env) => env.response_buffer_mut(),
            #[cfg(test)]
            EnvOrOwned::Owned { buffer, .. } => buffer,
        }
    }

    pub fn response_buffer_state(&mut self) -> &mut ResponseBufferState {
        match &mut self.env {
            EnvOrOwned::Env(env) => env.response_buffer_state(),
            #[cfg(test)]
            EnvOrOwned::Owned { state, .. } => state,
        }
    }

    pub fn remaining(&mut self) -> usize {
        self.response_buffer_mut().len() - self.length
    }

    pub fn write(mut self, data: &[u8]) -> Self {
        let offset = self.offset;
        let length = self.length;
        let buffer = self.response_buffer_mut();

        buffer[offset + length..offset + length + data.len()].copy_from_slice(data);
        self.length += data.len();

        self
    }

    pub fn prepend(mut self, data: &[u8]) -> Self {
        let offset = self.offset;
        let buffer = self.response_buffer_mut();

        assert!(
            offset >= data.len(),
            "Not enough space in buffer {} < {}",
            offset,
            data.len()
        );

        buffer[offset - data.len()..offset].copy_from_slice(data);
        self.offset -= data.len();
        self.length += data.len();

        self
    }

    pub fn abort(self) -> &'a mut dyn EapEnvironment {
        match self.env {
            EnvOrOwned::Env(env) => env,
            #[cfg(test)]
            EnvOrOwned::Owned { .. } => panic!("Cannot abort a test environment"),
        }
    }

    pub fn slice(&self) -> &[u8] {
        let buffer = self.response_buffer();
        let offset = self.offset;
        let length = self.length;
        &buffer[offset..offset + length]
    }

    pub fn build(mut self, code: MessageCode, identifier: u8) -> ResponseMessage<'a> {
        let mut header = [0u8; 4];
        header[0] = code as u8;
        header[1] = identifier;

        let total_length = self.length as u16 + 4;
        header[2..4].copy_from_slice(&total_length.to_be_bytes());
        self = self.prepend(&header);

        let length = self.length;
        let offset = self.offset;

        *self.response_buffer_state() = ResponseBufferState::Message { offset, length };

        ResponseMessage(self)
    }
}

#[cfg(test)]
impl<'a, 'b> From<&'a [u8]> for MessageBuilder<'b> {
    fn from(message: &'a [u8]) -> Self {
        // reserve space for the header
        let offset = 5;
        let mut buffer = vec![0u8; offset];
        buffer.extend_from_slice(message);

        let length = message.len();

        MessageBuilder {
            env: EnvOrOwned::Owned {
                buffer,
                state: ResponseBufferState::default(),
            },
            offset,
            length,
        }
    }
}

impl<'a> PartialEq for MessageBuilder<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.slice() == other.slice()
    }
}

impl<'a> Eq for MessageBuilder<'a> {}

#[derive(PartialEq, Eq)]
pub struct ResponseMessage<'a>(MessageBuilder<'a>);

impl<'a> ResponseMessage<'a> {
    pub fn slice(&self) -> &[u8] {
        self.0.slice()
    }
}

#[cfg(test)]
impl<'a> From<crate::message::Message<'a>> for ResponseMessage<'static> {
    fn from(message: crate::message::Message) -> Self {
        let buffer = message.to_vec();
        let length = buffer.len();

        let builder = MessageBuilder {
            env: EnvOrOwned::Owned {
                buffer,
                state: ResponseBufferState::default(),
            },
            offset: 0,
            length,
        };
        ResponseMessage(builder)
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_builder() {
        let mut env = DefaultEnvironment::new();
        let env: &mut dyn EapEnvironment = &mut env;

        let builder = env.respond().write(&[5, 6, 7, 8]).prepend(&[0]);
        let message = builder.build(MessageCode::Request, 0);

        assert_eq!(message.slice(), &[1, 0, 0, 9, 0, 5, 6, 7, 8]);
    }

    #[test]
    fn test_retransmit() {
        let mut org_env = DefaultEnvironment::new();
        let env: &mut dyn EapEnvironment = &mut org_env;

        let message = env
            .respond()
            .write(&[5, 6, 7, 8])
            .prepend(&[0])
            .build(MessageCode::Request, 0);

        let message_was = message.slice().to_vec();

        let env: &mut dyn EapEnvironment = &mut org_env;
        let stored = env.last_message().ok().unwrap().slice().to_vec();
        assert_eq!(message_was, stored);

        let env: &mut dyn EapEnvironment = &mut org_env;
        let stored = env.last_message().ok().unwrap().slice().to_vec();
        assert_eq!(message_was, stored);
    }
}
