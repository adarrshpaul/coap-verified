use hex_literal::hex;
use coap_verified::{CoapPacket, CoapEncoder, Type, Code, MessageId, CoapOption, OptionNumber, CoapError};

#[test]
fn test_rfc7252_sec8_example1_simple_get() {
    // RFC 7252 Section 8.1:
    // Header: CON, GET, MID=0x1234, TKL=0
    // Option: Uri-Path = "temperature" (Delta=11, Len=11 -> 0xBB, "temperature")
    // Payload: None
    let raw = hex!("40011234 bb 74656d7065726174757265");

    let packet = CoapPacket::parse(&raw).expect("Must parse valid RFC GET");
    assert_eq!(packet.msg_type, Type::Confirmable);
    assert_eq!(packet.code, Code::GET);
    assert_eq!(packet.message_id, MessageId(0x1234));
    assert_eq!(packet.token.len(), 0);
    assert_eq!(packet.payload.len(), 0);

    let mut opts = packet.options();
    let opt1 = opts.next().expect("Expected 1 option").expect("Valid option");
    assert_eq!(opt1.number, OptionNumber::URI_PATH);
    assert_eq!(opt1.value, b"temperature");
    assert!(opts.next().is_none());

    // Round-trip encoding
    let mut out = [0u8; 64];
    let len = CoapEncoder::encode(
        packet.msg_type,
        packet.code,
        packet.message_id,
        packet.token,
        &[opt1],
        packet.payload,
        &mut out,
    ).expect("Encode must succeed");

    assert_eq!(&out[..len], &raw);
}

#[test]
fn test_rfc7252_sec8_example2_piggybacked_response() {
    // RFC 7252 Section 8.1:
    // ACK, 2.05 Content, MID=0x1234, TKL=0
    // Payload: "22.3 C" with 0xFF marker
    let raw = hex!("60451234 ff 32322e332043");

    let packet = CoapPacket::parse(&raw).expect("Must parse piggybacked ACK");
    assert_eq!(packet.msg_type, Type::Acknowledgement);
    assert_eq!(packet.code, Code::CONTENT);
    assert_eq!(packet.message_id, MessageId(0x1234));
    assert_eq!(packet.token.len(), 0);
    assert_eq!(packet.payload, b"22.3 C");

    // Roundtrip
    let mut out = [0u8; 64];
    let len = CoapEncoder::encode(
        packet.msg_type,
        packet.code,
        packet.message_id,
        packet.token,
        &[],
        packet.payload,
        &mut out,
    ).expect("Encode must succeed");

    assert_eq!(&out[..len], &raw);
}

#[test]
fn test_rfc7252_edge_empty_payload_with_marker_must_fail() {
    // RFC 7252 Section 3: "The presence of a marker followed by a zero-length payload
    // MUST be processed as a message format error."
    let raw = hex!("40011234 ff");
    let res = CoapPacket::parse(&raw);
    assert_eq!(res, Err(CoapError::EmptyPayloadWithMarker));
}

#[test]
fn test_rfc7252_edge_token_length_greater_than_8_must_fail() {
    // RFC 7252 Section 3: "Lengths 9-15 are reserved, MUST NOT be sent, and MUST be
    // processed as a message format error."
    let mut raw = hex!("49011234010203040506070809"); // TKL = 9
    let res = CoapPacket::parse(&raw);
    assert_eq!(res, Err(CoapError::InvalidTokenLength(9)));

    raw[0] = 0x4F; // TKL = 15
    let res2 = CoapPacket::parse(&raw);
    assert_eq!(res2, Err(CoapError::InvalidTokenLength(15)));
}

#[test]
fn test_rfc7252_edge_delta_15_reserved_must_fail() {
    // RFC 7252 Section 3.1: "Value 15 is reserved for the Payload Marker and where the
    // Option Delta value of 15 is encountered, it MUST be processed as a message format error."
    let raw = hex!("40011234 f0 01");
    let res = CoapPacket::parse(&raw);
    assert_eq!(res, Err(CoapError::DeltaReserved15));
}

#[test]
fn test_rfc7252_edge_length_15_reserved_must_fail() {
    // RFC 7252 Section 3.1: "Value 15 is reserved for future use and MUST NOT be sent or accepted"
    let raw = hex!("40011234 0f");
    let res = CoapPacket::parse(&raw);
    assert_eq!(res, Err(CoapError::LengthReserved15));
}

#[test]
fn test_rfc7252_edge_options_out_of_order_must_fail() {
    // RFC 7252 Section 3.1: Options must be sorted by option number.
    // Let's create an option 11 (Uri-Path), followed by an attempt to decrement (delta cannot be negative, but let's test invalid ordering)
    let opt1 = CoapOption { number: 11, value: b"a" };
    let opt2 = CoapOption { number: 3, value: b"b" }; // Decreasing option number!

    let mut out = [0u8; 64];
    let res = CoapEncoder::encode(
        Type::Confirmable,
        Code::GET,
        MessageId(1),
        &[],
        &[opt1, opt2],
        &[],
        &mut out,
    );
    assert!(matches!(res, Err(CoapError::OptionsOutOfOrder { .. })));
}

#[test]
fn test_rfc7252_critical_option_classification() {
    // RFC 7252 Section 5.4.1: Critical if (number & 1) == 1
    assert!(OptionNumber::is_critical(OptionNumber::IF_MATCH)); // 1 -> critical
    assert!(OptionNumber::is_critical(OptionNumber::URI_HOST)); // 3 -> critical
    assert!(OptionNumber::is_critical(OptionNumber::URI_PORT)); // 7 -> critical
    assert!(OptionNumber::is_critical(OptionNumber::URI_PATH)); // 11 -> critical
    assert!(OptionNumber::is_critical(OptionNumber::URI_QUERY)); // 15 -> critical

    // Elective options (even numbers)
    assert!(!OptionNumber::is_critical(OptionNumber::ETAG)); // 4 -> elective
    assert!(!OptionNumber::is_critical(OptionNumber::CONTENT_FORMAT)); // 12 -> elective
    assert!(!OptionNumber::is_critical(OptionNumber::MAX_AGE)); // 14 -> elective
}
