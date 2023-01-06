use std::{
    error::Error,
    fmt::{Display, Formatter},
};

pub struct Message<'a> {
    pub code: MessageCode,
    pub identifier: u8,
    pub total_length: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub enum MessageParseError {
    InvalidLength,
    InvalidCode,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum MessageCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

impl Error for MessageParseError {}
impl Display for MessageParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageParseError::InvalidLength => write!(f, "Invalid length"),
            MessageParseError::InvalidCode => write!(f, "Invalid code"),
        }
    }
}

impl<'a> Message<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, MessageParseError> {
        if data.len() < 4 {
            return Err(MessageParseError::InvalidLength);
        }

        let code = match data[0] {
            1 => MessageCode::Request,
            2 => MessageCode::Response,
            3 => MessageCode::Success,
            4 => MessageCode::Failure,
            _ => {
                return Err(MessageParseError::InvalidCode);
            }
        };

        let identifier = data[1];
        let total_length = u16::from_be_bytes([data[2], data[3]]);

        if total_length as usize != data.len() + 4 {
            return Err(MessageParseError::InvalidLength);
        }

        Ok(Self {
            code,
            identifier,
            total_length,
            data: &data[4..],
        })
    }

    pub fn new(code: MessageCode, identifier: u8, data: &'a [u8]) -> Self {
        Self {
            code,
            identifier,
            total_length: (4 + data.len()) as u16,
            data,
        }
    }
}
