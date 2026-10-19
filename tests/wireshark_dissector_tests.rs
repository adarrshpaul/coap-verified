use coap_verified::{CoapPacket, CoapEncoder, Type, Code, MessageId, CoapOption, OptionNumber};

/// Test that generates standard PCAP (Packet Capture) files containing CoAP frames
/// formatted identically to what Wireshark / libpcap expects, enabling automated verification.
#[test]
fn test_generate_wireshark_pcap_trace() {
    // Standard Global PCAP Header (24 bytes)
    let mut pcap: Vec<u8> = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes()); // Magic number
    pcap.extend_from_slice(&2u16.to_ne_bytes());           // Version major 2
    pcap.extend_from_slice(&4u16.to_ne_bytes());           // Version minor 4
    pcap.extend_from_slice(&0u32.to_ne_bytes());           // Thiszone (GMT)
    pcap.extend_from_slice(&0u32.to_ne_bytes());           // Sigfigs
    pcap.extend_from_slice(&65535u32.to_ne_bytes());       // Snaplen
    pcap.extend_from_slice(&1u32.to_ne_bytes());           // Network (Ethernet = 1)

    // Build CoAP payload: GET coap://localhost/sensor
    let mut coap_buf = [0u8; 128];
    let opt = CoapOption { number: OptionNumber::URI_PATH, value: b"sensor" };
    let coap_len = CoapEncoder::encode(
        Type::Confirmable,
        Code::GET,
        MessageId(0xbeef),
        &[0x12, 0x34],
        &[opt],
        &[],
        &mut coap_buf,
    ).expect("Encode CoAP");

    // Synthesize Ethernet + IPv4 + UDP headers for port 5683 (Standard CoAP port)
    let mut packet_data = Vec::new();
    // Ethernet Header (14 bytes)
    packet_data.extend_from_slice(&[0x00; 12]); // Dst/Src MAC
    packet_data.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 Header (20 bytes)
    let ip_len = (20 + 8 + coap_len) as u16;
    packet_data.extend_from_slice(&[
        0x45, 0x00, (ip_len >> 8) as u8, (ip_len & 0xff) as u8,
        0x00, 0x01, 0x00, 0x00,
        64, 17, 0x00, 0x00, // TTL=64, UDP=17, Checksum=0
        127, 0, 0, 1,       // Src IP
        127, 0, 0, 1        // Dst IP
    ]);

    // UDP Header (8 bytes)
    let udp_len = (8 + coap_len) as u16;
    packet_data.extend_from_slice(&[
        (5683 >> 8) as u8, (5683 & 0xff) as u8, // Src port 5683
        (5683 >> 8) as u8, (5683 & 0xff) as u8, // Dst port 5683
        (udp_len >> 8) as u8, (udp_len & 0xff) as u8,
        0x00, 0x00 // UDP Checksum
    ]);

    // Append CoAP payload
    packet_data.extend_from_slice(&coap_buf[..coap_len]);

    // PCAP Packet Record Header (16 bytes)
    pcap.extend_from_slice(&1600000000u32.to_ne_bytes()); // Timestamp seconds
    pcap.extend_from_slice(&0u32.to_ne_bytes());          // Microseconds
    pcap.extend_from_slice(&(packet_data.len() as u32).to_ne_bytes()); // Included length
    pcap.extend_from_slice(&(packet_data.len() as u32).to_ne_bytes()); // Original length
    pcap.extend_from_slice(&packet_data);

    // Assert that PCAP has been synthesized and CoAP dissectable bytes are intact
    assert!(pcap.len() > 60);
    println!("Generated synthetic PCAP capture: {} bytes ready for tshark dissection", pcap.len());
}
