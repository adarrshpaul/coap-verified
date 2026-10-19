use crate::error::{CoapError, ParseResult};
use crate::message::{Code, MessageId, Type};
use crate::option::{CoapOption, OptionsIter};

/// Zero-copy parsed view over a raw CoAP byte buffer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapPacket<'a> {
    pub msg_type: Type,
    pub code: Code,
    pub message_id: MessageId,
    pub token: &'a [u8],
    options_slice: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> CoapPacket<'a> {
    pub fn parse(buf: &'a [u8]) -> ParseResult<Self> {
        if buf.len() < 4 {
            return Err(CoapError::UnexpectedEof);
        }

        let first = buf[0];
        let version = (first >> 6) & 0x03;
        if version != 1 {
            return Err(CoapError::InvalidVersion(version));
        }

        let msg_type = match (first >> 4) & 0x03 {
            0 => Type::Confirmable,
            1 => Type::NonConfirmable,
            2 => Type::Acknowledgement,
            3 => Type::Reset,
            _ => unreachable!(),
        };

        let tkl = (first & 0x0F) as usize;
        if tkl > 8 {
            return Err(CoapError::InvalidTokenLength(tkl));
        }

        let code = Code::from_u8(buf[1]);
        let message_id = MessageId(u16::from_be_bytes([buf[2], buf[3]]));

        let offset = 4;
        if buf.len() < offset + tkl {
            return Err(CoapError::UnexpectedEof);
        }

        let token = &buf[offset..offset + tkl];
        let remaining = &buf[offset + tkl..];

        // Find optional payload marker 0xFF
        let (options_slice, payload) = match remaining.iter().position(|&b| b == 0xFF) {
            Some(idx) => {
                let p = &remaining[idx + 1..];
                // RFC 7252 Section 3: The presence of a marker followed by a zero-length payload must be processed as a message format error
                if p.is_empty() {
                    return Err(CoapError::EmptyPayloadWithMarker);
                }
                (&remaining[..idx], p)
            }
            None => (remaining, &[][..]),
        };

        // Quick structural validation of options
        let iter = OptionsIter::new(options_slice);
        let mut prev = 0u16;
        for opt in iter {
            let o = opt?;
            if o.number < prev {
                return Err(CoapError::OptionsOutOfOrder {
                    prev,
                    current: o.number,
                });
            }
            prev = o.number;
        }

        Ok(Self {
            msg_type,
            code,
            message_id,
            token,
            options_slice,
            payload,
        })
    }

    pub fn options(&self) -> OptionsIter<'a> {
        OptionsIter::new(self.options_slice)
    }

    pub fn raw_options(&self) -> &'a [u8] {
        self.options_slice
    }
}

/// Zero-alloc streaming encoder
pub struct CoapEncoder;

impl CoapEncoder {
    pub fn encode(
        msg_type: Type,
        code: Code,
        message_id: MessageId,
        token: &[u8],
        options: &[CoapOption],
        payload: &[u8],
        out: &mut [u8],
    ) -> ParseResult<usize> {
        if token.len() > 8 {
            return Err(CoapError::InvalidTokenLength(token.len()));
        }

        let min_len = 4 + token.len() + if !payload.is_empty() { 1 + payload.len() } else { 0 };
        if out.len() < min_len {
            return Err(CoapError::BufferTooSmall);
        }

        // Header byte 0
        let ver = 1u8 << 6;
        let t = (msg_type as u8) << 4;
        let tkl = token.len() as u8;
        out[0] = ver | t | tkl;

        // Code
        out[1] = code.to_u8();

        // Message ID
        let mid_bytes = message_id.0.to_be_bytes();
        out[2] = mid_bytes[0];
        out[3] = mid_bytes[1];

        // Token
        out[4..4 + token.len()].copy_from_slice(token);
        let mut cursor = 4 + token.len();

        // Delta-encoded options
        let mut prev_opt = 0u16;
        for opt in options {
            if opt.number < prev_opt {
                return Err(CoapError::OptionsOutOfOrder {
                    prev: prev_opt,
                    current: opt.number,
                });
            }

            let delta = opt.number - prev_opt;
            let len = opt.value.len();

            let (d_nibble, d_extra, d_bytes) = Self::calc_delta_or_len(delta as usize)?;
            let (l_nibble, l_extra, l_bytes) = Self::calc_delta_or_len(len)?;

            let needed = 1 + d_bytes + l_bytes + len;
            if cursor + needed > out.len() {
                return Err(CoapError::BufferTooSmall);
            }

            out[cursor] = (d_nibble << 4) | l_nibble;
            cursor += 1;

            if d_bytes == 1 {
                out[cursor] = d_extra as u8;
                cursor += 1;
            } else if d_bytes == 2 {
                let b = (d_extra as u16).to_be_bytes();
                out[cursor] = b[0];
                out[cursor + 1] = b[1];
                cursor += 2;
            }

            if l_bytes == 1 {
                out[cursor] = l_extra as u8;
                cursor += 1;
            } else if l_bytes == 2 {
                let b = (l_extra as u16).to_be_bytes();
                out[cursor] = b[0];
                out[cursor + 1] = b[1];
                cursor += 2;
            }

            out[cursor..cursor + len].copy_from_slice(opt.value);
            cursor += len;
            prev_opt = opt.number;
        }

        // Payload
        if !payload.is_empty() {
            if cursor + 1 + payload.len() > out.len() {
                return Err(CoapError::BufferTooSmall);
            }
            out[cursor] = 0xFF; // Payload Marker
            cursor += 1;
            out[cursor..cursor + payload.len()].copy_from_slice(payload);
            cursor += payload.len();
        }

        Ok(cursor)
    }

    fn calc_delta_or_len(val: usize) -> ParseResult<(u8, usize, usize)> {
        if val < 13 {
            Ok((val as u8, 0, 0))
        } else if val <= 268 {
            Ok((13, val - 13, 1))
        } else if val <= 65804 {
            Ok((14, val - 269, 2))
        } else {
            Err(CoapError::BufferTooSmall)
        }
    }
}
