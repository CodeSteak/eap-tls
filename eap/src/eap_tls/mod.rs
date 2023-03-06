use std::ops::DerefMut;

use rustls::ConnectionCommon;
const TLS_LEN_FIELD_LEN: usize = 4;

pub struct CommonTLS<C> {
    pub con: Box<C>,
    pub sendbufferstate: SendBufferState,
    pub finished: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EapCommonResult {
    Finished,
    Next(Vec<u8>),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SendBufferState {
    NewPayload { total_length: usize },
    MidPayload,
}

impl<C> CommonTLS<C> {
    pub fn new(con: C) -> Self {
        Self {
            con: Box::new(con),
            sendbufferstate: SendBufferState::NewPayload { total_length: 0 },
            finished: false,
        }
    }
}

impl<C, T> CommonTLS<C>
where
    C: DerefMut<Target = ConnectionCommon<T>>,
{
    pub fn start_packet(&self) -> Vec<u8> {
        vec![Header {
            length_included: false,
            more_fragments: false,
            start: true,
        }
        .write()]
    }

    pub fn process(&mut self, msg: &[u8], return_on_finish: bool) -> Result<EapCommonResult, ()> {
        if msg.is_empty() {
            return Err(());
        }

        let header = Header::parse(msg[0]);
        let only_ack = header.more_fragments;

        let has_data = msg.len() > 1;
        if has_data || header.start {
            let mut payload: &[u8] = if header.length_included {
                if msg.len() < TLS_LEN_FIELD_LEN + 1 {
                    eprintln!("TLS: message too short");
                    return Err(());
                }
                &msg[(1 + TLS_LEN_FIELD_LEN)..]
            } else {
                &msg[1..]
            };

            let payload_len = payload.len();
            match self.con.read_tls(&mut payload) {
                Ok(n) if n == payload_len => { /* ok */ }
                Ok(n) => {
                    eprintln!("TLS read_tls: not all data consumed, {n} vs. {payload_len}",);
                    return Err(());
                }
                Err(e) => {
                    eprintln!("TLS Error {e}");
                    return Err(());
                }
            };

            match self.con.process_new_packets() {
                Ok(d) => {
                    self.sendbufferstate = SendBufferState::NewPayload {
                        total_length: d.tls_bytes_to_write(),
                    }
                }
                Err(e) => {
                    eprintln!("TLS Error {e}");
                    return Err(());
                }
            };
        }

        if !self.con.is_handshaking()
            && (matches!(
                self.sendbufferstate,
                SendBufferState::NewPayload { total_length: 0 }
            ) || matches!(self.sendbufferstate, SendBufferState::MidPayload))
        {
            self.finished = true;

            if return_on_finish {
                return Ok(EapCommonResult::Finished);
            }
        }

        if !only_ack {
            const MTU: usize = 512;

            let is_first = match self.sendbufferstate {
                SendBufferState::NewPayload { .. } => true,
                SendBufferState::MidPayload => false,
            };

            let mut result = vec![0; MTU];
            let (offset, mut courser) = match self.sendbufferstate {
                SendBufferState::NewPayload { total_length } => {
                    let len = (total_length) as u32;
                    result[1..=4].copy_from_slice(&len.to_be_bytes());
                    (5, &mut result[5..])
                }
                SendBufferState::MidPayload => (1, &mut result[1..]),
            };

            match self.con.write_tls(&mut courser) {
                Ok(n) => {
                    result.truncate(n + offset);
                }
                Err(e) => {
                    eprintln!("TLS Error {e}");
                    return Err(());
                }
            };

            let more_fragments = self.con.wants_write();
            let header = Header {
                length_included: is_first,
                more_fragments,
                start: false,
            };

            self.sendbufferstate = SendBufferState::MidPayload;

            result[0] = header.write();
            Ok(EapCommonResult::Next(result))
        } else {
            let result = vec![Header {
                length_included: false,
                more_fragments: false,
                start: false,
            }
            .write()];

            Ok(EapCommonResult::Next(result))
        }
    }
}

/*
https://www.rfc-editor.org/rfc/rfc5216

      0 1 2 3 4 5 6 7 8
      +-+-+-+-+-+-+-+-+
      |L M S R R R R R|
      +-+-+-+-+-+-+-+-+

      L = Length included
      M = More fragments
      S = EAP-TLS start
      R = Reserved

e.g.
0xC0 = 1100 0000
0xE0 = 1110 0000
*/

const HEADER_FIELD_LEN: u8 = 0b1000_0000;
const HEADER_FIELD_MORE_FRAGMENTS: u8 = 0b0100_0000;
const HEADER_FIELD_START: u8 = 0b0010_0000;

struct Header {
    length_included: bool,
    more_fragments: bool,
    start: bool,
}

impl Header {
    fn write(&self) -> u8 {
        let mut result = 0;
        if self.length_included {
            result |= HEADER_FIELD_LEN;
        }
        if self.more_fragments {
            result |= HEADER_FIELD_MORE_FRAGMENTS;
        }
        if self.start {
            result |= HEADER_FIELD_START;
        }
        result
    }

    fn parse(data: u8) -> Self {
        let length_included = (data & HEADER_FIELD_LEN) != 0;
        let more_fragments = (data & HEADER_FIELD_MORE_FRAGMENTS) != 0;
        let start = (data & HEADER_FIELD_START) != 0;

        Header {
            length_included,
            more_fragments,
            start,
        }
    }
}
