use std::net::{SocketAddr, UdpSocket};

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112A442;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const HEADER_LEN: usize = 20;
const TXN_LEN: usize = 12;
const SERVERS_ENV: &str = "NEXGUARD_STUN_SERVERS";
const DEFAULT_SERVERS: &str = "stun.l.google.com:19302,stun.cloudflare.com:3478";

pub fn servers() -> Vec<String> {
    std::env::var(SERVERS_ENV)
        .unwrap_or_else(|_| DEFAULT_SERVERS.to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn resolve(server: &str) -> Option<SocketAddr> {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Some(addr);
    }
    let mut resolved = std::net::ToSocketAddrs::to_socket_addrs(server).ok()?.peekable();
    let mut fallback = None;
    for addr in resolved.by_ref() {
        if addr.is_ipv4() {
            return Some(addr);
        }
        fallback.get_or_insert(addr);
    }
    fallback
}

pub fn is_binding_response(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN
        && u16::from_be_bytes([data[0], data[1]]) == BINDING_RESPONSE
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == MAGIC_COOKIE
}

pub struct Probe {
    txn: [u8; TXN_LEN],
}

impl Probe {
    pub fn send(socket: &UdpSocket, server: SocketAddr) -> Option<Self> {
        let mut txn = [0u8; TXN_LEN];
        crate::rng::fill(&mut txn);
        let request = build_binding_request(&txn);
        socket.send_to(&request, server).ok()?;
        Some(Self { txn })
    }

    pub fn parse(&self, data: &[u8]) -> Option<SocketAddr> {
        if !is_binding_response(data) || data[8..HEADER_LEN] != self.txn {
            return None;
        }
        parse_attributes(data)
    }
}

fn build_binding_request(txn: &[u8; TXN_LEN]) -> [u8; HEADER_LEN] {
    let mut pkt = [0u8; HEADER_LEN];
    pkt[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    pkt[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    pkt[8..HEADER_LEN].copy_from_slice(txn);
    pkt
}

fn parse_attributes(data: &[u8]) -> Option<SocketAddr> {
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let attr_end = (HEADER_LEN + msg_len).min(data.len());
    let mut pos = HEADER_LEN;

    while pos + 4 <= attr_end {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > attr_end {
            break;
        }
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => return parse_xor_mapped(&data[pos..pos + attr_len]),
            ATTR_MAPPED_ADDRESS => return parse_mapped(&data[pos..pos + attr_len]),
            _ => {}
        }
        pos = (pos + attr_len + 3) & !3;
    }
    None
}

fn parse_xor_mapped(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([data[2], data[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    match data[1] {
        0x01 if data.len() >= 8 => {
            let ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ MAGIC_COOKIE;
            Some(SocketAddr::new(std::net::Ipv4Addr::from(ip).into(), port))
        }
        0x02 if data.len() >= 20 => {
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[4..20]);
            for i in 0..4 {
                bytes[i] ^= cookie[i];
            }
            Some(SocketAddr::new(std::net::Ipv6Addr::from(bytes).into(), port))
        }
        _ => None,
    }
}

fn parse_mapped(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    match data[1] {
        0x01 if data.len() >= 8 => {
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some(SocketAddr::new(ip.into(), port))
        }
        0x02 if data.len() >= 20 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[4..20]);
            Some(SocketAddr::new(std::net::Ipv6Addr::from(bytes).into(), port))
        }
        _ => None,
    }
}
