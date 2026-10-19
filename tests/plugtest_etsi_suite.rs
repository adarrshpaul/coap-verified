use hex_literal::hex;
use coap_verified::{CoapPacket, CoapEncoder, Type, Code, MessageId, CoapOption, OptionNumber};

/// ETSI / C-Plugtest TD_COAP_CORE_01:
/// Perform GET request (CON mode) with Uri-Path.
/// Expected response: ACK with 2.05 Content or 2.04 Changed, same MID or matching Token.
#[test]
fn test_plugtest_td_coap_core_01_get_con() {
    let client_request = hex!("40010001 b474657374"); // CON, GET, MID=1, Uri-Path="test"
    let req = CoapPacket::parse(&client_request).expect("Valid request");
    
    assert_eq!(req.msg_type, Type::Confirmable);
    assert_eq!(req.code, Code::GET);
    assert_eq!(req.message_id, MessageId(1));

    // Server synthesizes piggybacked ACK response
    let mut server_resp_buf = [0u8; 128];
    let payload = b"Welcome to CoAP Plugtest";
    let len = CoapEncoder::encode(
        Type::Acknowledgement,
        Code::CONTENT,
        req.message_id,
        req.token,
        &[],
        payload,
        &mut server_resp_buf,
    ).expect("Encode response");

    let resp = CoapPacket::parse(&server_resp_buf[..len]).expect("Parse server response");
    assert_eq!(resp.msg_type, Type::Acknowledgement);
    assert_eq!(resp.code, Code::CONTENT);
    assert_eq!(resp.message_id, req.message_id); // Piggybacked ACK MUST match MID
    assert_eq!(resp.payload, payload);
}

/// ETSI / C-Plugtest TD_COAP_CORE_03:
/// Perform POST request with payload.
/// Expected response: 2.01 Created or 2.04 Changed with matching token.
#[test]
fn test_plugtest_td_coap_core_03_post_with_payload() {
    let client_token = [0xA1, 0xB2];
    let mut client_req_buf = [0u8; 128];
    let post_payload = b"sensor_val=42";
    
    let opt_path = CoapOption { number: OptionNumber::URI_PATH, value: b"sensors" };

    let req_len = CoapEncoder::encode(
        Type::Confirmable,
        Code::POST,
        MessageId(42),
        &client_token,
        &[opt_path],
        post_payload,
        &mut client_req_buf,
    ).expect("Encode POST");

    let req = CoapPacket::parse(&client_req_buf[..req_len]).expect("Parse POST");
    assert_eq!(req.msg_type, Type::Confirmable);
    assert_eq!(req.code, Code::POST);
    assert_eq!(req.token, &client_token[..]);
    assert_eq!(req.payload, post_payload);

    // Piggybacked response: 2.01 Created
    let mut resp_buf = [0u8; 128];
    let resp_len = CoapEncoder::encode(
        Type::Acknowledgement,
        Code::CREATED,
        req.message_id,
        req.token,
        &[],
        &[],
        &mut resp_buf,
    ).expect("Encode 2.01");

    let resp = CoapPacket::parse(&resp_buf[..resp_len]).expect("Parse 2.01");
    assert_eq!(resp.code, Code::CREATED);
    assert_eq!(resp.token, &client_token[..]);
}

/// ETSI / C-Plugtest TD_COAP_CORE_14:
/// Handling of Unknown Critical Options.
/// RFC 7252 Section 5.4.1: If an unknown critical option is encountered by a server,
/// it MUST return 4.02 (Bad Option).
#[test]
fn test_plugtest_td_coap_core_14_unknown_critical_option() {
    let unknown_critical_opt_num = 99u16; // 99 is odd -> Critical!
    assert!(OptionNumber::is_critical(unknown_critical_opt_num));

    let opt = CoapOption { number: unknown_critical_opt_num, value: b"critical_mystery" };
    let mut buf = [0u8; 64];
    let len = CoapEncoder::encode(
        Type::Confirmable,
        Code::GET,
        MessageId(100),
        &[],
        &[opt],
        &[],
        &mut buf,
    ).expect("Encode");

    let req = CoapPacket::parse(&buf[..len]).expect("Parse");
    
    // Simulate server option evaluation:
    let mut rejected_with_bad_option = false;
    for opt_res in req.options() {
        let o = opt_res.unwrap();
        // Check if server recognizes option
        let recognized = match o.number {
            OptionNumber::URI_PATH | OptionNumber::CONTENT_FORMAT => true,
            _ => false,
        };

        if !recognized && OptionNumber::is_critical(o.number) {
            rejected_with_bad_option = true;
            break;
        }
    }

    assert!(rejected_with_bad_option, "Server MUST reject unknown critical option with 4.02 Bad Option");
}
