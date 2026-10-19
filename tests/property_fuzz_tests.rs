use proptest::prelude::*;
use coap_verified::{CoapPacket, CoapEncoder, Type, Code, MessageId, CoapOption, CoapError};

proptest! {
    // Fuzz Invariant 1: Random bytes must NEVER panic
    #[test]
    fn fuzz_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        if let Ok(packet) = CoapPacket::parse(&bytes) {
            // Traverse options
            for opt in packet.options() {
                let _ = opt;
            }
        }
    }

    // Fuzz Invariant 2: Any valid encoded message must round-trip back to identical packet fields
    #[test]
    fn fuzz_roundtrip_valid_packets(
        t_val in 0u8..4,
        code_class in 0u8..8,
        code_detail in 0u8..32,
        mid in any::<u16>(),
        token in proptest::collection::vec(any::<u8>(), 0..=8),
        payload in proptest::collection::vec(any::<u8>(), 0..128)
    ) {
        let msg_type = Type::from_u8(t_val).unwrap();
        let code = Code { class: code_class, detail: code_detail };
        let message_id = MessageId(mid);

        let mut out = [0u8; 1024];
        if let Ok(len) = CoapEncoder::encode(
            msg_type,
            code,
            message_id,
            &token,
            &[],
            &payload,
            &mut out
        ) {
            let parsed = CoapPacket::parse(&out[..len]).expect("Validly encoded packet must be parseable");
            prop_assert_eq!(parsed.msg_type, msg_type);
            prop_assert_eq!(parsed.code, code);
            prop_assert_eq!(parsed.message_id, message_id);
            prop_assert_eq!(parsed.token, &token[..]);
            prop_assert_eq!(parsed.payload, &payload[..]);
        }
    }
}
