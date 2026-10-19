use crate::error::{CoapError, ParseResult};

pub mod OptionNumber {
    pub const IF_MATCH: u16 = 1;
    pub const URI_HOST: u16 = 3;
    pub const ETAG: u16 = 4;
    pub const IF_NONE_MATCH: u16 = 5;
    pub const URI_PORT: u16 = 7;
    pub const LOCATION_PATH: u16 = 8;
    pub const URI_PATH: u16 = 11;
    pub const CONTENT_FORMAT: u16 = 12;
    pub const MAX_AGE: u16 = 14;
    pub const URI_QUERY: u16 = 15;
    pub const ACCEPT: u16 = 17;
    pub const LOCATION_QUERY: u16 = 20;
    pub const BLOCK2: u16 = 23;
    pub const BLOCK1: u16 = 27;
    pub const SIZE2: u16 = 28;
    pub const PROXY_URI: u16 = 35;
    pub const PROXY_SCHEME: u16 = 39;
    pub const SIZE1: u16 = 60;

    /// RFC 7252 Section 5.4.1: An option is critical if the least significant bit is 1.
    pub const fn is_critical(number: u16) -> bool {
        (number & 1) == 1
    }

    /// RFC 7252 Section 5.4.2: An option is unsafe if bit 5 is 1 (counting LSB as bit 0).
    pub const fn is_unsafe(number: u16) -> bool {
        (number & 2) == 2
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoapOption<'a> {
    pub number: u16,
    pub value: &'a [u8],
}

/// Zero-allocation lazy iterator over RFC 7252 Delta-Encoded Options
#[derive(Debug, Clone)]
pub struct OptionsIter<'a> {
    slice: &'a [u8],
    offset: usize,
    current_option_number: u16,
}

impl<'a> OptionsIter<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        Self {
            slice,
            offset: 0,
            current_option_number: 0,
        }
    }
}

impl<'a> Iterator for OptionsIter<'a> {
    type Item = ParseResult<CoapOption<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.slice.len() {
            return None;
        }

        let first = self.slice[self.offset];
        self.offset += 1;

        let delta_nibble = (first >> 4) & 0x0F;
        let len_nibble = first & 0x0F;

        // RFC 7252: delta 15 is reserved for payload marker, not allowed in options
        if delta_nibble == 15 {
            return Some(Err(CoapError::DeltaReserved15));
        }
        if len_nibble == 15 {
            return Some(Err(CoapError::LengthReserved15));
        }

        // Parse extended delta
        let delta: u16 = match delta_nibble {
            0..=12 => delta_nibble as u16,
            13 => {
                if self.offset >= self.slice.len() {
                    return Some(Err(CoapError::UnexpectedEof));
                }
                let val = self.slice[self.offset] as u16 + 13;
                self.offset += 1;
                val
            }
            14 => {
                if self.offset + 1 >= self.slice.len() {
                    return Some(Err(CoapError::UnexpectedEof));
                }
                let val = u16::from_be_bytes([self.slice[self.offset], self.slice[self.offset + 1]]) + 269;
                self.offset += 2;
                val
            }
            _ => unreachable!(),
        };

        // Parse extended length
        let length: usize = match len_nibble {
            0..=12 => len_nibble as usize,
            13 => {
                if self.offset >= self.slice.len() {
                    return Some(Err(CoapError::UnexpectedEof));
                }
                let val = self.slice[self.offset] as usize + 13;
                self.offset += 1;
                val
            }
            14 => {
                if self.offset + 1 >= self.slice.len() {
                    return Some(Err(CoapError::UnexpectedEof));
                }
                let val = u16::from_be_bytes([self.slice[self.offset], self.slice[self.offset + 1]]) as usize + 269;
                self.offset += 2;
                val
            }
            _ => unreachable!(),
        };

        let new_option_number = self.current_option_number.saturating_add(delta);

        // RFC 7252 Section 3.1: Options must appear in order of option number
        if new_option_number < self.current_option_number {
            return Some(Err(CoapError::OptionsOutOfOrder {
                prev: self.current_option_number,
                current: new_option_number,
            }));
        }

        if self.offset + length > self.slice.len() {
            return Some(Err(CoapError::UnexpectedEof));
        }

        let value = &self.slice[self.offset..self.offset + length];
        self.offset += length;
        self.current_option_number = new_option_number;

        Some(Ok(CoapOption {
            number: new_option_number,
            value,
        }))
    }
}
