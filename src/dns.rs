use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub const MAGIC_DNS_IP: &str = "100.100.100.100";
const DNS_PORT: u16 = 53;
const UPSTREAM_TIMEOUT_MS: u64 = 3000;
const DNS_SUFFIX: &str = ".nexguard";

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QTYPE_PTR: u16 = 12;
const QCLASS_IN: u16 = 1;

pub struct DnsResolver {
    peers: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    socket: UdpSocket,
    upstream: SocketAddr,
    active: Arc<AtomicBool>,
}

impl DnsResolver {
    pub fn try_start(upstream: &str, peers: Arc<RwLock<HashMap<String, Ipv4Addr>>>) -> Option<Self> {
        let bind_addr = format!("{}:{}", MAGIC_DNS_IP, DNS_PORT);
        let socket = UdpSocket::bind(&bind_addr)
            .or_else(|_| UdpSocket::bind(format!("127.0.0.1:{}", DNS_PORT)))
            .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
            .ok()?;
        socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
        socket.set_nonblocking(true).ok();

        let upstream_addr: SocketAddr = format!("{}:53", upstream)
            .parse()
            .or_else(|_| "1.1.1.1:53".parse())
            .ok()?;

        Some(Self {
            peers,
            socket,
            upstream: upstream_addr,
            active: Arc::new(AtomicBool::new(true)),
        })
    }

    pub fn run_with_shutdown(&self, shutdown: &AtomicBool) {
        self.run_loop(shutdown);
    }

    fn run_loop(&self, shutdown: &AtomicBool) {
        let mut buf = [0u8; 1500];
        let forward_sock = UdpSocket::bind("0.0.0.0:0").ok();
        if let Some(ref s) = forward_sock {
            s.set_read_timeout(Some(Duration::from_millis(UPSTREAM_TIMEOUT_MS))).ok();
        }

        while self.active.load(Ordering::Relaxed) && !shutdown.load(Ordering::Relaxed) {
            match self.socket.recv_from(&mut buf) {
                Ok((n, src)) => {
                    if n < 12 { continue; }
                    let response = self.handle_query(&buf[..n], forward_sock.as_ref());
                    if !response.is_empty() {
                        let _ = self.socket.send_to(&response, src);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    fn handle_query(&self, query: &[u8], forward_sock: Option<&UdpSocket>) -> Vec<u8> {
        let qtype = u16::from_be_bytes([query[4], query[5]]);

        let name = match parse_qname(query, 12) {
            Some(n) => n.to_lowercase(),
            None => return Vec::new(),
        };

        match qtype {
            QTYPE_A => {
                if let Some(ip) = self.resolve(&name) {
                    return build_a_response(query, ip);
                }
                if name.ends_with(DNS_SUFFIX) {
                    return build_nxdomain(query);
                }
            }
            QTYPE_AAAA => {
                if name.ends_with(DNS_SUFFIX) {
                    return build_nxdomain(query);
                }
            }
            QTYPE_PTR => {
                return Vec::new();
            }
            _ => {}
        }

        if let Some(sock) = forward_sock {
            return self.forward(query, sock);
        }
        Vec::new()
    }

    fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let bare = name.strip_suffix(DNS_SUFFIX).unwrap_or(name);
        let bare = bare.strip_suffix('.').unwrap_or(bare);
        let peers = self.peers.read().ok()?;
        peers.get(bare).copied()
    }

    fn forward(&self, query: &[u8], sock: &UdpSocket) -> Vec<u8> {
        if sock.send_to(query, self.upstream).is_err() {
            return Vec::new();
        }
        let mut buf = [0u8; 1500];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => buf[..n].to_vec(),
            Err(_) => Vec::new(),
        }
    }
}

pub fn extract_peer_map(peer_infos: &[crate::api::MeshPeerInfo]) -> HashMap<String, Ipv4Addr> {
    let mut map = HashMap::new();
    for peer in peer_infos {
        if peer.name.is_empty() { continue; }
        for cidr in &peer.allowed_ips {
            if let Some(ip) = parse_ip_from_cidr(cidr) {
                map.insert(peer.name.clone(), ip);
                break;
            }
        }
    }
    map
}

fn parse_ip_from_cidr(cidr: &str) -> Option<Ipv4Addr> {
    let ip_str = cidr.split('/').next()?;
    ip_str.parse().ok()
}

fn parse_qname(data: &[u8], offset: usize) -> Option<String> {
    let mut pos = offset;
    let mut name = String::new();
    let mut jumped = false;
    let mut max_jumps = 5;

    loop {
        if pos >= data.len() { return None; }
        let len = data[pos] as usize;
        if len == 0 { break; }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() { return None; }
            let ptr = ((len & 0x3f) << 8 | data[pos + 1] as usize) as usize;
            if !jumped { jumped = true; }
            pos = ptr;
            max_jumps -= 1;
            if max_jumps == 0 { return None; }
            continue;
        }
        pos += 1;
        if pos + len > data.len() { return None; }
        if !name.is_empty() { name.push('.'); }
        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
        pos += len;
    }
    Some(name)
}

fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let qname_end = find_qname_end(query, 12).unwrap_or(query.len());
    let mut resp = Vec::with_capacity(qname_end + 16);
    resp.extend_from_slice(&query[..12]);
    resp[2] |= 0x80;
    resp[3] |= 0x80;
    resp[6..8].copy_from_slice(&1u16.to_be_bytes());
    resp[8..10].copy_from_slice(&0u16.to_be_bytes());
    resp[10..12].copy_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&query[12..qname_end]);

    let ip_bytes = ip.octets();
    resp.extend_from_slice(&0xc00cu16.to_be_bytes());
    resp.extend_from_slice(&QTYPE_A.to_be_bytes());
    resp.extend_from_slice(&QCLASS_IN.to_be_bytes());
    resp.extend_from_slice(&32u32.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip_bytes);
    resp
}

fn build_nxdomain(query: &[u8]) -> Vec<u8> {
    let qname_end = find_qname_end(query, 12).unwrap_or(query.len());
    let mut resp = Vec::with_capacity(qname_end);
    resp.extend_from_slice(&query[..qname_end]);
    if resp.len() >= 12 {
        resp[2] |= 0x80;
        resp[3] |= 0x83;
        resp[6..8].copy_from_slice(&0u16.to_be_bytes());
        resp[8..10].copy_from_slice(&0u16.to_be_bytes());
        resp[10..12].copy_from_slice(&0u16.to_be_bytes());
    }
    resp
}

fn find_qname_end(data: &[u8], offset: usize) -> Option<usize> {
    let mut pos = offset;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 { return Some(pos + 5); }
        if len & 0xc0 == 0xc0 { return Some(pos + 6); }
        pos += 1 + len;
    }
    None
}
