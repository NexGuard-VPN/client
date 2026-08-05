use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112A442;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const DISCOVERY_TIMEOUT_SECS: u64 = 3;

const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

pub fn discover_public_endpoint_on_port(local_port: u16) -> Option<SocketAddr> {
    for server in DEFAULT_STUN_SERVERS {
        if let Some(ep) = try_discover_on_port(server, local_port) {
            return Some(ep);
        }
    }
    None
}

fn try_discover_on_port(server: &str, local_port: u16) -> Option<SocketAddr> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", local_port)).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(DISCOVERY_TIMEOUT_SECS))).ok();
    let server_addr = resolve_addr(server)?;
    let txn_id = generate_txn_id();
    let request = build_binding_request(&txn_id);
    socket.send_to(&request, server_addr).ok()?;
    let mut buf = [0u8; 512];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    if n < 20 { return None; }
    parse_binding_response(&buf[..n], &txn_id)
}

fn resolve_addr(addr: &str) -> Option<SocketAddr> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Some(sa);
    }
    std::net::ToSocketAddrs::to_socket_addrs(addr).ok()?.next()
}

fn generate_txn_id() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos() as u64;
    let mut id = [0u8; 12];
    id[..8].copy_from_slice(&nanos.to_be_bytes());
    id[8..12].copy_from_slice(&(nanos.wrapping_mul(0x517cc1b727220a95) as u32).to_be_bytes());
    id
}

fn build_binding_request(txn_id: &[u8; 12]) -> [u8; 20] {
    let mut pkt = [0u8; 20];
    pkt[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    pkt[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    pkt[8..20].copy_from_slice(txn_id);
    pkt
}

fn parse_binding_response(data: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 20 { return None; }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_RESPONSE { return None; }
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE { return None; }
    if &data[8..20] != txn_id { return None; }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let attr_end = (20 + msg_len).min(data.len());
    let mut pos = 20;

    while pos + 4 <= attr_end {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > attr_end { break; }
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => return parse_xor_mapped(&data[pos..pos + attr_len]),
            ATTR_MAPPED_ADDRESS => return parse_mapped(&data[pos..pos + attr_len]),
            _ => {}
        }
        pos += attr_len;
        pos = (pos + 3) & !3;
    }
    None
}

fn parse_xor_mapped(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 4 { return None; }
    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;
    match family {
        0x01 if data.len() >= 8 => {
            let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ip = xor_ip ^ MAGIC_COOKIE;
            Some(SocketAddr::new(std::net::Ipv4Addr::from(ip).into(), port))
        }
        0x02 if data.len() >= 20 => {
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            for i in 0..4 { ip_bytes[i] ^= cookie_bytes[i]; }
            Some(SocketAddr::new(std::net::Ipv6Addr::from(ip_bytes).into(), port))
        }
        _ => None,
    }
}

fn parse_mapped(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 4 { return None; }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);
    match family {
        0x01 if data.len() >= 8 => {
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some(SocketAddr::new(ip.into(), port))
        }
        0x02 if data.len() >= 20 => {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            Some(SocketAddr::new(std::net::Ipv6Addr::from(ip_bytes).into(), port))
        }
        _ => None,
    }
}
