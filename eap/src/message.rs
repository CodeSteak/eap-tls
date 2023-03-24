use std::{
    error::Error,
    fmt::{Display, Formatter},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Message {
    pub code: MessageCode,
    pub identifier: u8,
    pub total_length: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum MessageParseError {
    InvalidLength,
    InvalidCode,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

impl Message {
    pub fn parse(data: &[u8]) -> Result<Self, MessageParseError> {
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

        if total_length as usize != data.len() {
            return Err(MessageParseError::InvalidLength);
        }

        Ok(Self {
            code,
            identifier,
            total_length,
            data: data[4..].to_vec(),
        })
    }

    pub fn new(code: MessageCode, identifier: u8, data: &[u8]) -> Self {
        Self {
            code,
            identifier,
            total_length: (4 + data.len()) as u16,
            data: data.to_vec(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        self.write(&mut buffer).unwrap();
        buffer
    }

    pub fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[self.code as u8, self.identifier])?;
        writer.write_all(&self.total_length.to_be_bytes())?;
        writer.write_all(&self.data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(hex: &str) -> Vec<u8> {
        let mut buffer = vec![];
        for p in hex.trim().split_ascii_whitespace() {
            buffer.push(u8::from_str_radix(p, 16).unwrap());
        }
        buffer
    }

    #[test]
    fn parse_simple() {
        assert_eq!(
            Message {
                identifier: 0x59,
                code: MessageCode::Response,
                total_length: 0x0009,
                data: hex("01 75 73 65 72"),
            },
            Message::parse(&hex("02 59 00 09 01 75 73 65 72")).unwrap(),
        )
    }
}
