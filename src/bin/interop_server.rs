use tokio::net::UdpSocket;
use coap_verified::{CoapPacket, CoapEncoder, Type, Code};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = match UdpSocket::bind("127.0.0.1:5683").await {
        Ok(s) => s,
        Err(_) => UdpSocket::bind("127.0.0.1:56883").await?,
    };

    let local_addr = socket.local_addr()?;
    println!("SERVER_READY:{}", local_addr.port());

    let mut buf = [0u8; 1500];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let req_bytes = &buf[..len];

        match CoapPacket::parse(req_bytes) {
            Ok(packet) => {
                if packet.code == Code::GET {
                    let mut resp_buf = [0u8; 1500];
                    let payload = b"Hello from Rust CoAP Verified!";
                    let resp_len = CoapEncoder::encode(
                        Type::Acknowledgement,
                        Code::CONTENT,
                        packet.message_id,
                        packet.token,
                        &[],
                        payload,
                        &mut resp_buf,
                    ).unwrap();

                    socket.send_to(&resp_buf[..resp_len], peer).await?;
                }
            }
            Err(e) => {
                eprintln!("Rejected malformed packet from {}: {:?}", peer, e);
            }
        }
    }
}
