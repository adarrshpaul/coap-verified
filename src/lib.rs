#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod codec;
pub mod option;
pub mod message;
pub mod error;

pub use codec::{CoapPacket, CoapEncoder};
pub use message::{Type, Code, MessageId};
pub use option::{OptionNumber, CoapOption, OptionsIter};
pub use error::{CoapError, ParseResult};
