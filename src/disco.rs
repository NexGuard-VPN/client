use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hmac::Mac;

pub const MAGIC: [u8; 4] = *b"NGD\x01";
pub const PING: u8 = 0x01;
pub const PONG: u8 = 0x02;

const KIND_OFF: usize = 4;
const SENDER_OFF: usize = 5;
const COUNTER_OFF: usize = 37;
const MAC_OFF: usize = 45;
const HEADER_LEN: usize = 77;
const MAC_LEN: usize = 32;
const TX_ID_LEN: usize = 8;
const ADDR_LEN: usize = 19;
const FAMILY_V4: u8 = 0x01;
const FAMILY_V6: u8 = 0x02;

pub struct Message {
    pub kind: u8,
    pub sender: [u8; 32],
    pub counter: u64,
    pub tx_id: [u8; TX_ID_LEN],
    pub observed: Option<SocketAddr>,
}

pub fn is_disco(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN && data[..MAGIC.len()] == MAGIC
}

pub fn encode(
    secret: &[u8],
    kind: u8,
    sender: &[u8; 32],
    counter: u64,
    tx_id: &[u8; TX_ID_LEN],
    observed: Option<SocketAddr>,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(TX_ID_LEN + ADDR_LEN);
    payload.extend_from_slice(tx_id);
    if let Some(addr) = observed {
        encode_addr(&mut payload, addr);
    }

    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&MAGIC);
    frame.push(kind);
    frame.extend_from_slice(sender);
    frame.extend_from_slice(&counter.to_be_bytes());
    frame.extend_from_slice(&[0u8; MAC_LEN]);
    frame.extend_from_slice(&payload);

    let mac = compute_mac(secret, kind, sender, counter, &payload);
    frame[MAC_OFF..MAC_OFF + MAC_LEN].copy_from_slice(&mac);
    frame
}

pub fn decode(secret: &[u8], data: &[u8]) -> Option<Message> {
    if !is_disco(data) {
        return None;
    }
    let kind = data[KIND_OFF];
    if kind != PING && kind != PONG {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&data[SENDER_OFF..COUNTER_OFF]);
    let counter = u64::from_be_bytes(data[COUNTER_OFF..MAC_OFF].try_into().ok()?);
    let payload = &data[HEADER_LEN..];
    if payload.len() < TX_ID_LEN {
        return None;
    }

    let expected = compute_mac(secret, kind, &sender, counter, payload);
    if !constant_time_eq(&expected, &data[MAC_OFF..MAC_OFF + MAC_LEN]) {
        return None;
    }

    let mut tx_id = [0u8; TX_ID_LEN];
    tx_id.copy_from_slice(&payload[..TX_ID_LEN]);
    Some(Message {
        kind,
        sender,
        counter,
        tx_id,
        observed: decode_addr(&payload[TX_ID_LEN..]),
    })
}

fn compute_mac(secret: &[u8], kind: u8, sender: &[u8; 32], counter: u64, payload: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(secret)
        .expect("hmac accepts any key length");
    mac.update(&MAGIC);
    mac.update(&[kind]);
    mac.update(sender);
    mac.update(&counter.to_be_bytes());
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn encode_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(FAMILY_V4);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&[0u8; 12]);
        }
        IpAddr::V6(ip) => {
            out.push(FAMILY_V6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn decode_addr(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < ADDR_LEN {
        return None;
    }
    let port = u16::from_be_bytes([data[17], data[18]]);
    match data[0] {
        FAMILY_V4 => {
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            Some(SocketAddr::new(ip.into(), port))
        }
        FAMILY_V6 => {
            let bytes: [u8; 16] = data[1..17].try_into().ok()?;
            Some(SocketAddr::new(Ipv6Addr::from(bytes).into(), port))
        }
        _ => None,
    }
}
