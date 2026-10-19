#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoapError {
    UnexpectedEof,
    InvalidVersion(u8),
    InvalidTokenLength(usize),
    EmptyPayloadWithMarker,
    DeltaReserved15,
    LengthReserved15,
    OptionsOutOfOrder { prev: u16, current: u16 },
    BufferTooSmall,
    CriticalOptionNotRecognized(u16),
}

pub type ParseResult<T> = Result<T, CoapError>;
