#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Type {
    Confirmable = 0,
    NonConfirmable = 1,
    Acknowledgement = 2,
    Reset = 3,
}

impl Type {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Type::Confirmable),
            1 => Some(Type::NonConfirmable),
            2 => Some(Type::Acknowledgement),
            3 => Some(Type::Reset),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageId(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code {
    pub class: u8,  // 3 bits (0..7)
    pub detail: u8, // 5 bits (0..31)
}

impl Code {
    pub const EMPTY: Self = Code { class: 0, detail: 0 };
    pub const GET: Self = Code { class: 0, detail: 1 };
    pub const POST: Self = Code { class: 0, detail: 2 };
    pub const PUT: Self = Code { class: 0, detail: 3 };
    pub const DELETE: Self = Code { class: 0, detail: 4 };

    // 2.xx Success
    pub const CREATED: Self = Code { class: 2, detail: 1 };
    pub const DELETED: Self = Code { class: 2, detail: 2 };
    pub const VALID: Self = Code { class: 2, detail: 3 };
    pub const CHANGED: Self = Code { class: 2, detail: 4 };
    pub const CONTENT: Self = Code { class: 2, detail: 5 };

    // 4.xx Client Error
    pub const BAD_REQUEST: Self = Code { class: 4, detail: 0 };
    pub const UNAUTHORIZED: Self = Code { class: 4, detail: 1 };
    pub const BAD_OPTION: Self = Code { class: 4, detail: 2 };
    pub const FORBIDDEN: Self = Code { class: 4, detail: 3 };
    pub const NOT_FOUND: Self = Code { class: 4, detail: 4 };
    pub const METHOD_NOT_ALLOWED: Self = Code { class: 4, detail: 5 };
    pub const NOT_ACCEPTABLE: Self = Code { class: 4, detail: 6 };

    // 5.xx Server Error
    pub const INTERNAL_SERVER_ERROR: Self = Code { class: 5, detail: 0 };
    pub const NOT_IMPLEMENTED: Self = Code { class: 5, detail: 1 };
    pub const BAD_GATEWAY: Self = Code { class: 5, detail: 2 };
    pub const SERVICE_UNAVAILABLE: Self = Code { class: 5, detail: 3 };
    pub const GATEWAY_TIMEOUT: Self = Code { class: 5, detail: 4 };

    pub fn to_u8(self) -> u8 {
        ((self.class & 0x07) << 5) | (self.detail & 0x1F)
    }

    pub fn from_u8(val: u8) -> Self {
        Self {
            class: (val >> 5) & 0x07,
            detail: val & 0x1F,
        }
    }

    pub fn is_request(&self) -> bool {
        self.class == 0 && self.detail != 0
    }

    pub fn is_response(&self) -> bool {
        self.class >= 2
    }

    pub fn is_empty(&self) -> bool {
        self.class == 0 && self.detail == 0
    }
}
