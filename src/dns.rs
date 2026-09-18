use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::protect;

const DNS_PORT: u16 = 53;
const LOOPBACK: &str = "127.0.0.1";
const BIND_ATTEMPTS: u32 = 10;
const BIND_RETRY: Duration = Duration::from_millis(200);

fn bind_with_retry(bind_ip: &str) -> Option<UdpSocket> {
    for attempt in 0..BIND_ATTEMPTS {
        if let Ok(socket) = UdpSocket::bind(format!("{}:{}", bind_ip, DNS_PORT)) {
            return Some(socket);
        }
        if attempt + 1 < BIND_ATTEMPTS {
            std::thread::sleep(BIND_RETRY);
        }
    }
    None
}
const UPSTREAM_TIMEOUT_MS: u64 = 3000;
pub const DEFAULT_DNS_SUFFIX: &str = "nexguard";
pub const DEFAULT_UPSTREAM: &str = "1.1.1.1";
/// The address the mesh answers names on when it cannot bind a socket the
/// system will route to it. It sits outside the mesh CIDR so a host can point
/// its tunnel at it without spending a mesh address on the resolver.
pub const RESOLVER: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);

/// The bare zone every peer name lives under, as the host should advertise it.
pub fn zone_name(suffix: &str) -> String {
    let trimmed = suffix.trim().trim_matches('.');
    let base = if trimmed.is_empty() { DEFAULT_DNS_SUFFIX } else { trimmed };
    base.to_lowercase()
}

fn normalize_suffix(suffix: &str) -> String {
    format!(".{}", zone_name(suffix))
}

const HEADER_LEN: usize = 12;
const QTYPE_A: u16 = 1;
const QCLASS_IN: u16 = 1;

/// What a query deserves once the mesh has looked at it.
pub enum Reply {
    Ready(Vec<u8>),
    Upstream,
    Drop,
}

pub trait Upstream: Send + Sync {
    fn exchange(&self, query: &[u8]) -> Option<Vec<u8>>;
}

pub struct UdpUpstream {
    server: SocketAddr,
}

impl UdpUpstream {
    pub fn open(server: &str) -> Option<Self> {
        let server: SocketAddr = format!("{}:{}", server, DNS_PORT)
            .parse()
            .or_else(|_| format!("{}:{}", DEFAULT_UPSTREAM, DNS_PORT).parse())
            .ok()?;
        Some(Self { server })
    }
}

impl Upstream for UdpUpstream {
    /// A socket of its own per query: several queries are in flight at once
    /// and answers must not cross between them. On Android the socket has to
    /// be held out of our own tunnel or the query would come back to us.
    fn exchange(&self, query: &[u8]) -> Option<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        protect::hold(&socket).ok()?;
        socket
            .set_read_timeout(Some(Duration::from_millis(UPSTREAM_TIMEOUT_MS)))
            .ok()?;
        socket.send_to(query, self.server).ok()?;
        let mut buf = [0u8; 1500];
        let (n, from) = socket.recv_from(&mut buf).ok()?;
        (from == self.server).then(|| buf[..n].to_vec())
    }
}

/// The names the mesh owns. It answers a query without caring how the query
/// reached it, so the socket the desktop binds and the packets a phone hands us
/// share one set of answers.
pub struct Zone {
    peers: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    suffix: String,
}

impl Zone {
    pub fn new(suffix: &str, peers: Arc<RwLock<HashMap<String, Ipv4Addr>>>) -> Self {
        Self { peers, suffix: normalize_suffix(suffix) }
    }

    pub fn answer(&self, query: &[u8]) -> Reply {
        let question = match parse_question(query) {
            Some(question) => question,
            None => return Reply::Drop,
        };

        if question.qtype == QTYPE_A {
            if let Some(ip) = self.resolve(&question.name) {
                return Reply::Ready(build_a_response(query, question.end, ip));
            }
        }
        // A name in the mesh zone is ours to answer or to deny, whatever was
        // asked of it: it never reaches a resolver outside the tunnel.
        if question.name.ends_with(&self.suffix) {
            return Reply::Ready(build_nxdomain(query, question.end));
        }

        Reply::Upstream
    }

    fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let bare = name.strip_suffix(&self.suffix).unwrap_or(name);
        let bare = bare.strip_suffix('.').unwrap_or(bare);
        let peers = self.peers.read().ok()?;
        peers.get(bare).copied()
    }
}

pub struct DnsResolver {
    zone: Zone,
    socket: UdpSocket,
    upstream: Option<UdpUpstream>,
    active: Arc<AtomicBool>,
}

impl DnsResolver {
    pub fn try_start(
        bind_ip: &str,
        upstream: &str,
        suffix: &str,
        peers: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    ) -> Option<Self> {
        let socket = bind_with_retry(bind_ip)
            .or_else(|| UdpSocket::bind(format!("{}:{}", LOOPBACK, DNS_PORT)).ok())?;
        socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
        socket.set_nonblocking(true).ok();

        Some(Self {
            zone: Zone::new(suffix, peers),
            socket,
            upstream: UdpUpstream::open(upstream),
            active: Arc::new(AtomicBool::new(true)),
        })
    }

    pub fn resolver_address(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok().filter(|a| a.port() == DNS_PORT)
    }

    pub fn run_with_shutdown(&self, shutdown: &AtomicBool) {
        self.run_loop(shutdown);
    }

    fn run_loop(&self, shutdown: &AtomicBool) {
        let mut buf = [0u8; 1500];

        while self.active.load(Ordering::Relaxed) && !shutdown.load(Ordering::Relaxed) {
            match self.socket.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let response = match self.zone.answer(&buf[..n]) {
                        Reply::Ready(response) => response,
                        Reply::Upstream => self
                            .upstream
                            .as_ref()
                            .and_then(|upstream| upstream.exchange(&buf[..n]))
                            .unwrap_or_default(),
                        Reply::Drop => Vec::new(),
                    };
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
}

struct Question {
    name: String,
    qtype: u16,
    end: usize,
}

fn parse_question(query: &[u8]) -> Option<Question> {
    if query.len() < HEADER_LEN {
        return None;
    }
    let end = find_qname_end(query, HEADER_LEN).filter(|end| *end <= query.len())?;
    let name = parse_qname(query, HEADER_LEN)?.to_lowercase();
    let qtype = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    Some(Question { name, qtype, end })
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

fn build_a_response(query: &[u8], qname_end: usize, ip: Ipv4Addr) -> Vec<u8> {
    let mut resp = Vec::with_capacity(qname_end + 16);
    resp.extend_from_slice(&query[..HEADER_LEN]);
    resp[2] |= 0x80;
    resp[3] |= 0x80;
    resp[6..8].copy_from_slice(&1u16.to_be_bytes());
    resp[8..10].copy_from_slice(&0u16.to_be_bytes());
    resp[10..12].copy_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&query[HEADER_LEN..qname_end]);

    let ip_bytes = ip.octets();
    resp.extend_from_slice(&0xc00cu16.to_be_bytes());
    resp.extend_from_slice(&QTYPE_A.to_be_bytes());
    resp.extend_from_slice(&QCLASS_IN.to_be_bytes());
    resp.extend_from_slice(&32u32.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip_bytes);
    resp
}

fn build_nxdomain(query: &[u8], qname_end: usize) -> Vec<u8> {
    let mut resp = Vec::with_capacity(qname_end);
    resp.extend_from_slice(&query[..qname_end]);
    resp[2] |= 0x80;
    resp[3] |= 0x83;
    resp[6..8].copy_from_slice(&0u16.to_be_bytes());
    resp[8..10].copy_from_slice(&0u16.to_be_bytes());
    resp[10..12].copy_from_slice(&0u16.to_be_bytes());
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
