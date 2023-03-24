mod wrapper;

use message::{Message, MessageCode};
pub use wrapper::*;
#[cfg(feature = "tls")]
mod eap_tls;
mod layers;
mod message;
pub mod util;

#[cfg(feature = "tls")]
pub use dummycert::TlsConfig;

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

trait EapEnvironmentResponse<'a>: Sized {
    fn respond(self) -> MessageBuilder<'a>;
    fn last_message(self) -> Result<ResponseMessage<'a>, Self>;

    fn respond_with(
        self,
        code: MessageCode,
        identifier: u8,
        content: &[u8],
    ) -> ResponseMessage<'a> {
        let mut builder = self.respond();
        builder.write(content);
        builder.build(code, identifier)
    }
}

impl<'a> EapEnvironmentResponse<'a> for &'a mut dyn EapEnvironment {
    fn respond(self) -> MessageBuilder<'a> {
        *self.response_buffer_state() = ResponseBufferState::Dirty;
        MessageBuilder {
            env: self,
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
                    env: self,
                    offset,
                    length,
                };
                Ok(ResponseMessage::Builder(builder))
            }
            _ => Err(self),
        }
    }
}

pub struct MessageBuilder<'a> {
    env: &'a mut dyn EapEnvironment,
    length: usize,
    offset: usize,
}

impl<'a> MessageBuilder<'a> {
    pub fn remaining(&mut self) -> usize {
        self.env.response_buffer_mut().len() - self.length
    }

    pub fn write(&mut self, data: &[u8]) {
        let buffer = self.env.response_buffer_mut();
        let offset = self.offset;
        let length = self.length;
        buffer[offset + length..offset + length + data.len()].copy_from_slice(data);
        self.length += data.len();
    }

    pub fn prepend(&mut self, data: &[u8]) {
        let buffer = self.env.response_buffer_mut();
        let offset = self.offset;
        buffer[offset - data.len()..offset].copy_from_slice(data);
        self.offset -= data.len();
        self.length += data.len();
    }

    pub fn abort(self) -> &'a mut dyn EapEnvironment {
        self.env
    }

    fn slice(&self) -> &[u8] {
        let buffer = self.env.response_buffer();
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
        self.prepend(&header);

        *self.env.response_buffer_state() = ResponseBufferState::Message {
            offset: self.offset,
            length: self.length,
        };

        ResponseMessage::Builder(self)
    }
}

pub enum ResponseMessage<'a> {
    Builder(MessageBuilder<'a>),
    #[cfg(test)]
    Owned(Vec<u8>),
}

#[cfg(test)]
impl From<Message> for ResponseMessage<'static> {
    fn from(val: Message) -> Self {
        ResponseMessage::Owned(val.to_bytes())
    }
}

impl<'a> ResponseMessage<'a> {
    pub fn slice(&self) -> &[u8] {
        match self {
            ResponseMessage::Builder(builder) => builder.slice(),
            #[cfg(test)]
            ResponseMessage::Owned(data) => data.as_slice(),
        }
    }
}

impl<'a> PartialEq for ResponseMessage<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.slice() == other.slice()
    }
}

impl<'a> Eq for ResponseMessage<'a> {}

pub struct DefaultEnvironment {
    name: Option<Vec<u8>>,
    response_buffer: Box<[u8; 1024]>,
    response_buffer_state: ResponseBufferState,
}

impl DefaultEnvironment {
    pub fn new() -> Self {
        Self {
            name: None,
            response_buffer: Box::new([0u8; 1024]),
            response_buffer_state: ResponseBufferState::default(),
        }
    }
}

impl EapEnvironment for DefaultEnvironment {
    fn set_name(&mut self, name: &[u8]) {
        self.name = Some(name.to_vec());
    }

    fn name(&self) -> Option<&[u8]> {
        self.name.as_deref()
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
