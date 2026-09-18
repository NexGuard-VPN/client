use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
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
const ANY_PORT: u16 = 0;
const MESSAGE_BUFFER: usize = 1500;
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
const FLAGS_AT: usize = 2;
const TRUNCATED: u8 = 0x02;
const COUNTS_AT: usize = 4;
const SECTIONS: usize = 4;
const QUESTION: usize = 0;
const ADDITIONAL: usize = 3;
const QUESTION_LEN: usize = 4;
const RECORD_LEN: usize = 10;
const RDLENGTH_AT: usize = 8;
const COUNT_LEN: usize = 2;
const ARCOUNT_AT: usize = COUNTS_AT + ADDITIONAL * COUNT_LEN;
const OPT_TYPE: u16 = 41;
const OPT_CLASS_AT: usize = 2;
const OPT_CLASS_LEN: usize = 2;
const OPT_FLAGS: u32 = 0;
const OPT_RDLENGTH: u16 = 0;
const ROOT_NAME: u8 = 0;
const ZONE_SEPARATOR: char = '%';

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
        let server = address_of(server).or_else(|| address_of(DEFAULT_UPSTREAM))?;
        Some(Self { server })
    }

    /// The answer has to come from the resolver we asked. Only the address and
    /// the port decide that: an IPv6 answer carries a scope the address we
    /// dialled does not, and comparing whole sockets would reject it.
    fn spoken_by_server(&self, from: SocketAddr) -> bool {
        from.ip() == self.server.ip() && from.port() == self.server.port()
    }
}

/// A resolver of either family, written bare (`1.1.1.1`, `2606:4700:4700::1111`,
/// `[::1]`) or with a port of its own. An IPv6-only network can advertise a
/// link-local resolver, which is an address plus the interface it is local to
/// (`fe80::1%wlan0`); no address parser takes that zone, so it is read off here
/// and carried as the scope the socket needs to reach it.
fn address_of(server: &str) -> Option<SocketAddr> {
    let trimmed = server.trim();
    let bare = trimmed
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(trimmed);
    if let Some((address, zone)) = bare.split_once(ZONE_SEPARATOR) {
        return scoped(address, zone);
    }
    match bare.parse::<IpAddr>() {
        Ok(ip) => Some(SocketAddr::new(ip, DNS_PORT)),
        Err(_) => trimmed.parse().ok(),
    }
}

fn scoped(address: &str, zone: &str) -> Option<SocketAddr> {
    let ip = address.parse().ok()?;
    Some(SocketAddr::V6(SocketAddrV6::new(ip, DNS_PORT, 0, scope_id(zone)?)))
}

/// A zone is either the index itself or the name of an interface, which only
/// the host can turn into an index.
fn scope_id(zone: &str) -> Option<u32> {
    zone.parse().ok().or_else(|| interface_index(zone))
}

#[cfg(unix)]
fn interface_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => None,
        index => Some(index),
    }
}

#[cfg(not(unix))]
fn interface_index(_name: &str) -> Option<u32> {
    None
}

impl Upstream for UdpUpstream {
    /// A socket of its own per query: several queries are in flight at once
    /// and answers must not cross between them. It is bound in the resolver's
    /// own family, because an IPv6-only network hands us an IPv6 resolver that
    /// no IPv4 socket can reach. On Android the socket has to be held out of
    /// our own tunnel or the query would come back to us.
    fn exchange(&self, query: &[u8]) -> Option<Vec<u8>> {
        let unspecified = match self.server {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let socket = UdpSocket::bind(SocketAddr::new(unspecified, ANY_PORT)).ok()?;
        protect::hold(&socket).ok()?;
        socket
            .set_read_timeout(Some(Duration::from_millis(UPSTREAM_TIMEOUT_MS)))
            .ok()?;
        socket.send_to(query, self.server).ok()?;
        let mut buf = [0u8; MESSAGE_BUFFER];
        let (n, from) = socket.recv_from(&mut buf).ok()?;
        self.spoken_by_server(from).then(|| buf[..n].to_vec())
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
        let mut buf = [0u8; MESSAGE_BUFFER];

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
    Some(name_end(data, offset)? + QUESTION_LEN)
}

fn name_end(data: &[u8], offset: usize) -> Option<usize> {
    let mut pos = offset;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 { return Some(pos + 1); }
        if len & 0xc0 == 0xc0 { return Some(pos + 2); }
        pos += 1 + len;
    }
    None
}

fn record_end(data: &[u8], offset: usize, section: usize) -> Option<usize> {
    let end = name_end(data, offset)?;
    if section == QUESTION {
        return Some(end + QUESTION_LEN);
    }
    let rdlength = data.get(end + RDLENGTH_AT..end + RECORD_LEN)?;
    Some(end + RECORD_LEN + u16::from_be_bytes([rdlength[0], rdlength[1]]) as usize)
}

fn section_count(message: &[u8], section: usize) -> u16 {
    let at = COUNTS_AT + section * 2;
    u16::from_be_bytes([message[at], message[at + 1]])
}

/// Fits a reply into what the path back to the client can carry. Anything
/// longer comes back cut to the records that still fit and marked truncated,
/// because a client handed nothing at all learns nothing and waits out its
/// whole timeout, while the TC bit sends it straight to TCP.
pub fn fit(reply: &[u8], capacity: usize) -> Option<Cow<'_, [u8]>> {
    if reply.len() <= capacity {
        return Some(Cow::Borrowed(reply));
    }
    if capacity < HEADER_LEN || reply.len() < HEADER_LEN {
        return None;
    }
    let mut kept = [0u16; SECTIONS];
    let mut end = HEADER_LEN;
    'sections: for section in 0..SECTIONS {
        for _ in 0..section_count(reply, section) {
            match record_end(reply, end, section) {
                Some(next) if next <= capacity => {
                    end = next;
                    kept[section] += 1;
                }
                _ => break 'sections,
            }
        }
    }
    let mut short = reply[..end].to_vec();
    short[FLAGS_AT] |= TRUNCATED;
    for (section, count) in kept.iter().enumerate() {
        let at = COUNTS_AT + section * 2;
        short[at..at + 2].copy_from_slice(&count.to_be_bytes());
    }
    Some(Cow::Owned(short))
}

/// Where a query states the largest reply it can take, if it states one at all:
/// EDNS0 keeps that size in the CLASS field of an OPT record rather than in a
/// class of its own.
enum Advertised {
    At(usize),
    Absent,
    Unreadable,
}

fn advertised(query: &[u8]) -> Advertised {
    if query.len() < HEADER_LEN {
        return Advertised::Unreadable;
    }
    let mut end = HEADER_LEN;
    for section in 0..SECTIONS {
        for _ in 0..section_count(query, section) {
            let (Some(name), Some(next)) = (name_end(query, end), record_end(query, end, section))
            else {
                return Advertised::Unreadable;
            };
            if next > query.len() {
                return Advertised::Unreadable;
            }
            if section == ADDITIONAL && query[name..].starts_with(&OPT_TYPE.to_be_bytes()) {
                return Advertised::At(name + OPT_CLASS_AT);
            }
            end = next;
        }
    }
    // Bytes past the last record are bytes we did not understand. Writing an
    // OPT record after them would hand the resolver a message it can only
    // refuse, and the whole query with it.
    if end == query.len() {
        Advertised::Absent
    } else {
        Advertised::Unreadable
    }
}

/// Lowers what a forwarded query asks to be answered with to what the path home
/// can carry. A longer reply would have to be cut by `fit`, and we serve no TCP
/// for a client to retry the truncation on, so the resolver is asked for a
/// length it can cut coherently itself and `fit` stays the backstop for a
/// resolver that ignores us. A query asking for less keeps its own size.
pub fn clamp(query: &[u8], capacity: usize) -> Cow<'_, [u8]> {
    let room = u16::try_from(capacity).unwrap_or(u16::MAX);
    match advertised(query) {
        Advertised::At(class) => {
            if u16::from_be_bytes([query[class], query[class + 1]]) <= room {
                return Cow::Borrowed(query);
            }
            let mut lowered = query.to_vec();
            lowered[class..class + OPT_CLASS_LEN].copy_from_slice(&room.to_be_bytes());
            Cow::Owned(lowered)
        }
        Advertised::Absent => asking(query, room).map_or(Cow::Borrowed(query), Cow::Owned),
        Advertised::Unreadable => Cow::Borrowed(query),
    }
}

/// A query that states no size is given the OPT record it lacks, which is also
/// what makes it an EDNS0 query in the first place.
fn asking(query: &[u8], room: u16) -> Option<Vec<u8>> {
    let additional = section_count(query, ADDITIONAL).checked_add(1)?;
    let mut extended = query.to_vec();
    extended[ARCOUNT_AT..ARCOUNT_AT + COUNT_LEN].copy_from_slice(&additional.to_be_bytes());
    extended.push(ROOT_NAME);
    extended.extend_from_slice(&OPT_TYPE.to_be_bytes());
    extended.extend_from_slice(&room.to_be_bytes());
    extended.extend_from_slice(&OPT_FLAGS.to_be_bytes());
    extended.extend_from_slice(&OPT_RDLENGTH.to_be_bytes());
    Some(extended)
}

#[cfg(test)]
mod upstream_tests {
    use super::*;
    use std::sync::mpsc::{channel, Receiver};

    const QUERY: &[u8] = b"a query on the wire";
    const ANSWER: &[u8] = b"an answer on the wire";
    const ANY_V4: &str = "127.0.0.1:0";
    const ANY_V6: &str = "[::1]:0";
    const PUBLIC_V6: &str = "2606:4700:4700::1111";
    const LINK_LOCAL: &str = "fe80::1";
    const FIRST_INTERFACE: u32 = 1;
    const NO_SUCH_INTERFACE: &str = "nexguard-not-an-interface";

    /// A resolver on loopback. An impostor answers from a socket of its own, so
    /// the reply carries an address the upstream never asked.
    fn resolver(bind: &str, impostor: bool) -> (String, Receiver<Vec<u8>>) {
        let server = UdpSocket::bind(bind).expect("a loopback resolver");
        let address = server.local_addr().expect("the resolver's address");
        let speaker = if impostor {
            UdpSocket::bind(bind).expect("a second loopback socket")
        } else {
            server.try_clone().expect("the resolver's own socket")
        };
        let (asked, queries) = channel();
        // A resolver that is never asked has to give up, or a test that expects
        // a query would wait on the channel for good.
        server
            .set_read_timeout(Some(Duration::from_millis(UPSTREAM_TIMEOUT_MS)))
            .expect("a resolver that gives up");
        std::thread::spawn(move || {
            let mut buf = [0u8; MESSAGE_BUFFER];
            let Ok((n, from)) = server.recv_from(&mut buf) else { return };
            let _ = speaker.send_to(ANSWER, from);
            let _ = asked.send(buf[..n].to_vec());
        });
        (address.to_string(), queries)
    }

    #[test]
    fn a_resolver_written_as_a_bare_address_keeps_its_family_and_the_dns_port() {
        let v6 = UdpUpstream::open(PUBLIC_V6).expect("an IPv6 resolver");
        let v4 = UdpUpstream::open(DEFAULT_UPSTREAM).expect("an IPv4 resolver");

        assert_eq!(v6.server, SocketAddr::new(PUBLIC_V6.parse().unwrap(), DNS_PORT));
        assert_eq!(v4.server, SocketAddr::new(DEFAULT_UPSTREAM.parse().unwrap(), DNS_PORT));
        assert_eq!(UdpUpstream::open("[::1]").unwrap().server.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(UdpUpstream::open("not an address").unwrap().server, v4.server);
    }

    #[test]
    fn an_ipv6_resolver_is_reached_and_its_answer_comes_back() {
        let (address, queries) = resolver(ANY_V6, false);
        let upstream = UdpUpstream::open(&address).expect("an IPv6 resolver");

        let answer = upstream.exchange(QUERY);

        assert!(upstream.server.is_ipv6());
        assert_eq!(answer.as_deref(), Some(ANSWER));
        assert_eq!(queries.recv().expect("the resolver was asked"), QUERY);
    }

    #[test]
    fn an_ipv4_resolver_is_reached_and_its_answer_comes_back() {
        let (address, queries) = resolver(ANY_V4, false);
        let upstream = UdpUpstream::open(&address).expect("an IPv4 resolver");

        let answer = upstream.exchange(QUERY);

        assert!(upstream.server.is_ipv4());
        assert_eq!(answer.as_deref(), Some(ANSWER));
        assert_eq!(queries.recv().expect("the resolver was asked"), QUERY);
    }

    #[test]
    fn an_answer_from_an_address_we_never_asked_is_refused_in_both_families() {
        for bind in [ANY_V4, ANY_V6] {
            let (address, queries) = resolver(bind, true);
            let upstream = UdpUpstream::open(&address).expect("a loopback resolver");

            assert_eq!(upstream.exchange(QUERY), None, "{}", bind);
            assert_eq!(queries.recv().expect("the resolver was asked"), QUERY);
        }
    }
    /// What the host calls the interface at a given index. A name written in
    /// here would be a different interface, or none, on the next platform.
    #[cfg(unix)]
    fn interface_name(index: u32) -> String {
        let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
        let resolved = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
        assert!(!resolved.is_null(), "the host has an interface at index {}", index);
        unsafe { std::ffi::CStr::from_ptr(resolved) }.to_string_lossy().into_owned()
    }

    #[test]
    #[cfg(unix)]
    fn a_link_local_resolver_keeps_the_interface_it_is_link_local_to() {
        let name = interface_name(FIRST_INTERFACE);
        let expected = SocketAddr::V6(SocketAddrV6::new(
            LINK_LOCAL.parse().expect("a link-local address"),
            DNS_PORT,
            0,
            FIRST_INTERFACE,
        ));

        for written in [
            format!("{}%{}", LINK_LOCAL, name),
            format!("[{}%{}]", LINK_LOCAL, name),
            format!("{}%{}", LINK_LOCAL, FIRST_INTERFACE),
        ] {
            assert_eq!(address_of(&written), Some(expected), "{}", written);
        }
    }

    #[test]
    fn a_resolver_on_an_interface_this_host_does_not_have_falls_back_to_the_default() {
        let written = format!("{}%{}", LINK_LOCAL, NO_SUCH_INTERFACE);

        assert_eq!(address_of(&written), None);
        assert_eq!(
            UdpUpstream::open(&written).expect("a resolver").server,
            address_of(DEFAULT_UPSTREAM).expect("the default resolver")
        );
    }
}

#[cfg(test)]
mod truncation_tests {
    use super::*;

    const PATTERNS: [u8; 5] = [0x00, 0x01, 0xc0, 0xff, 0x41];
    const CAPACITY: usize = 1252;
    const LARGER_THAN_THE_PATH: u16 = 4096;
    const SMALLER_THAN_THE_PATH: u16 = 512;
    const OPT_RECORD_LEN: usize = 11;
    const NAME: &str = "example.com";

    /// A query as a stub resolver writes it, either plain or stating the size it
    /// can take an answer in. The bytes are written out here rather than taken
    /// from the code under test, which would only agree with itself.
    fn query(states: Option<u16>) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in NAME.split('.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        if let Some(size) = states {
            message[10..12].copy_from_slice(&1u16.to_be_bytes());
            message.push(0);
            message.extend_from_slice(&[0, 41]);
            message.extend_from_slice(&size.to_be_bytes());
            message.extend_from_slice(&[0; 6]);
        }
        message
    }

    /// The size a message states, found by walking it as a resolver would
    /// rather than by looking where the clamp writes.
    fn stated(message: &[u8]) -> Option<u16> {
        let mut at = HEADER_LEN;
        for section in 0..SECTIONS {
            for _ in 0..section_count(message, section) {
                let name = name_end(message, at)?;
                let record = message.get(name..name + RECORD_LEN)?;
                if section == ADDITIONAL
                    && u16::from_be_bytes([record[0], record[1]]) == OPT_TYPE
                {
                    return Some(u16::from_be_bytes([record[2], record[3]]));
                }
                at = record_end(message, at, section)?;
            }
        }
        None
    }

    fn additional(message: &[u8]) -> u16 {
        section_count(message, ADDITIONAL)
    }

    #[test]
    fn nothing_a_resolver_can_send_back_breaks_the_fit() {
        for pattern in PATTERNS {
            for length in 0..=HEADER_LEN * 4 {
                let reply = vec![pattern; length];
                for capacity in 0..=HEADER_LEN * 2 {
                    let Some(fitted) = fit(&reply, capacity) else { continue };
                    assert!(fitted.len() <= capacity);
                    if fitted.len() < reply.len() {
                        assert!(fitted.len() >= HEADER_LEN);
                        assert_eq!(fitted[FLAGS_AT] & TRUNCATED, TRUNCATED);
                    }
                }
            }
        }
    }

    #[test]
    fn a_reply_that_fits_is_handed_on_word_for_word() {
        let reply = vec![0xab; HEADER_LEN];

        assert_eq!(fit(&reply, reply.len()).as_deref(), Some(reply.as_slice()));
        assert!(matches!(fit(&reply, reply.len()), Some(Cow::Borrowed(_))));
        assert_eq!(fit(&reply, HEADER_LEN - 1), None, "a path this narrow cannot say TC");
    }
    #[test]
    fn a_query_stating_no_size_leaves_stating_what_the_path_home_carries() {
        let bare = query(None);

        let clamped = clamp(&bare, CAPACITY);

        assert_eq!(stated(&clamped), Some(CAPACITY as u16));
        assert_eq!(additional(&clamped), additional(&bare) + 1);
        assert_eq!(clamped.len(), bare.len() + OPT_RECORD_LEN);
        assert_eq!(&clamped[..COUNTS_AT], &bare[..COUNTS_AT], "the client's id and flags");
        assert_eq!(&clamped[HEADER_LEN..bare.len()], &bare[HEADER_LEN..], "and its question");
    }

    #[test]
    fn a_query_stating_more_than_the_path_carries_is_lowered_and_nothing_else() {
        let asking_for_more = query(Some(LARGER_THAN_THE_PATH));

        let clamped = clamp(&asking_for_more, CAPACITY);

        assert_eq!(stated(&clamped), Some(CAPACITY as u16));
        assert_eq!(additional(&clamped), additional(&asking_for_more));
        let class = asking_for_more.len() - OPT_RECORD_LEN + 1 + OPT_CLASS_AT;
        let mut put_back = clamped.to_vec();
        put_back[class..class + OPT_CLASS_LEN]
            .copy_from_slice(&LARGER_THAN_THE_PATH.to_be_bytes());
        assert_eq!(put_back, asking_for_more, "only the size was rewritten");
    }

    #[test]
    fn a_query_stating_less_than_the_path_carries_keeps_its_own_size() {
        let modest = query(Some(SMALLER_THAN_THE_PATH));
        let exact = query(Some(CAPACITY as u16));

        for asked in [&modest, &exact] {
            let clamped = clamp(asked, CAPACITY);
            assert!(matches!(clamped, Cow::Borrowed(_)), "{:?}", stated(asked));
            assert_eq!(clamped.as_ref(), asked.as_slice());
        }
        // A path wider than any size a query can state still lowers nothing.
        let greedy = query(Some(LARGER_THAN_THE_PATH));
        assert_eq!(clamp(&greedy, usize::MAX).as_ref(), greedy.as_slice());
    }

    #[test]
    fn a_query_cut_short_or_nonsense_reaches_the_resolver_byte_for_byte() {
        for states in [None, Some(LARGER_THAN_THE_PATH)] {
            let whole = query(states);
            for cut in 0..whole.len() {
                let short = &whole[..cut];
                assert_eq!(clamp(short, CAPACITY).as_ref(), short, "cut at {}", cut);
            }
        }
        for pattern in PATTERNS {
            for length in 0..=HEADER_LEN * 4 {
                let message = vec![pattern; length];
                let clamped = clamp(&message, CAPACITY);
                // Anything the clamp does touch it has to leave a resolver able
                // to read, which is more than "it was not corrupted".
                if clamped.as_ref() != message.as_slice() {
                    let asked = stated(&clamped);
                    assert_eq!(asked, Some(CAPACITY as u16), "{:#x}/{}", pattern, length);
                }
            }
        }
    }
}
