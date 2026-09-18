//! Magic DNS for a tunnel the core does not own the settings of. iOS and
//! Android keep the resolver configuration to themselves and hand us the
//! descriptor, so a query never arrives on a socket we could bind: it arrives
//! as an IP packet addressed to `dns::RESOLVER`, and the answer has to be
//! written back into the tunnel the same way.

use std::net::Ipv4Addr;
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};

use crate::dns::{self, Reply, Upstream, Zone};

const IPV4_VERSION: u8 = 4;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const PROTO_UDP: u8 = 17;
const DNS_PORT: u16 = 53;
const TTL: u8 = 64;
const DONT_FRAGMENT: u8 = 0x40;
const PENDING_QUERIES: usize = 32;
const FORWARDERS: usize = 4;

struct Client {
    address: Ipv4Addr,
    port: u16,
}

struct Exchange {
    client: Client,
    query: Vec<u8>,
}

pub struct PacketDns {
    zone: Zone,
    capacity: usize,
    pending: Option<SyncSender<Exchange>>,
    answered: Sender<Vec<u8>>,
    ready: Receiver<Vec<u8>>,
}

impl PacketDns {
    pub fn new(zone: Zone, upstream: Option<Box<dyn Upstream>>, mtu: usize) -> Self {
        let (answered, ready) = channel();
        let capacity = mtu.saturating_sub(IPV4_HEADER_LEN + UDP_HEADER_LEN);
        // A name the mesh does not own is resolved off the packet loop, which
        // carries the whole tunnel and cannot wait on a resolver. Android sends
        // every query its apps make here, so one slow name must not hold up the
        // rest: a few forwarders share the queue.
        let pending = upstream.map(|upstream| {
            let (queries, waiting) = sync_channel(PENDING_QUERIES);
            let upstream: Arc<dyn Upstream> = Arc::from(upstream);
            let waiting = Arc::new(Mutex::new(waiting));
            for _ in 0..FORWARDERS {
                let upstream = Arc::clone(&upstream);
                let waiting = Arc::clone(&waiting);
                let answered = answered.clone();
                std::thread::spawn(move || forward(upstream, waiting, answered, capacity));
            }
            queries
        });
        Self { zone, capacity, pending, answered, ready }
    }

    /// Takes the packets addressed to the resolver and leaves every other
    /// packet to the caller, which is the whole of the tunnel's traffic.
    pub fn intercept(&self, packet: &[u8]) -> bool {
        let (client, query) = match query_in(packet) {
            Some(query) => query,
            None => return false,
        };
        match self.zone.answer(query) {
            Reply::Ready(response) => self.deliver(&client, &response),
            Reply::Upstream => {
                if let Some(pending) = self.pending.as_ref() {
                    let _ = pending.try_send(Exchange { client, query: query.to_vec() });
                }
            }
            Reply::Drop => {}
        }
        true
    }

    pub fn reply(&self) -> Option<Vec<u8>> {
        self.ready.try_recv().ok()
    }

    fn deliver(&self, client: &Client, response: &[u8]) {
        if let Some(packet) = datagram(client, response, self.capacity) {
            let _ = self.answered.send(packet);
        }
    }
}

fn forward(
    upstream: Arc<dyn Upstream>,
    waiting: Arc<Mutex<Receiver<Exchange>>>,
    answered: Sender<Vec<u8>>,
    capacity: usize,
) {
    loop {
        let taken = {
            let Ok(queue) = waiting.lock() else { return };
            queue.recv()
        };
        let Ok(exchange) = taken else { return };
        let Some(response) = upstream.exchange(&exchange.query) else {
            continue;
        };
        let Some(packet) = datagram(&exchange.client, &response, capacity) else {
            continue;
        };
        if answered.send(packet).is_err() {
            return;
        }
    }
}

fn query_in(packet: &[u8]) -> Option<(Client, &[u8])> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != IPV4_VERSION || packet[9] != PROTO_UDP {
        return None;
    }
    if Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]) != dns::RESOLVER {
        return None;
    }
    let header_len = (packet[0] & 0x0f) as usize * 4;
    if header_len < IPV4_HEADER_LEN {
        return None;
    }
    let total = (u16::from_be_bytes([packet[2], packet[3]]) as usize).min(packet.len());
    let udp = packet.get(header_len..total)?;
    if udp.len() < UDP_HEADER_LEN {
        return None;
    }
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if length < UDP_HEADER_LEN || length > udp.len() {
        return None;
    }
    if u16::from_be_bytes([udp[2], udp[3]]) != DNS_PORT {
        return None;
    }
    let client = Client {
        address: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        port: u16::from_be_bytes([udp[0], udp[1]]),
    };
    Some((client, &udp[UDP_HEADER_LEN..length]))
}

fn datagram(client: &Client, payload: &[u8], capacity: usize) -> Option<Vec<u8>> {
    if payload.is_empty() || payload.len() > capacity {
        return None;
    }
    let total = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = (IPV4_VERSION << 4) | (IPV4_HEADER_LEN / 4) as u8;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[6] = DONT_FRAGMENT;
    packet[8] = TTL;
    packet[9] = PROTO_UDP;
    packet[12..16].copy_from_slice(&dns::RESOLVER.octets());
    packet[16..20].copy_from_slice(&client.address.octets());
    let header = checksum(total_of(&packet[..IPV4_HEADER_LEN]));
    packet[10..12].copy_from_slice(&header.to_be_bytes());

    packet[IPV4_HEADER_LEN..IPV4_HEADER_LEN + 2].copy_from_slice(&DNS_PORT.to_be_bytes());
    packet[IPV4_HEADER_LEN + 2..IPV4_HEADER_LEN + 4].copy_from_slice(&client.port.to_be_bytes());
    let length = (UDP_HEADER_LEN + payload.len()) as u16;
    packet[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 6].copy_from_slice(&length.to_be_bytes());
    packet[IPV4_HEADER_LEN + UDP_HEADER_LEN..].copy_from_slice(payload);
    // A zero checksum means "not computed" on the wire, so the one case that
    // folds to zero is sent as its equivalent complement instead.
    let udp = match checksum(pseudo_header(client.address, length) + total_of(&packet[IPV4_HEADER_LEN..])) {
        0 => u16::MAX,
        sum => sum,
    };
    packet[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].copy_from_slice(&udp.to_be_bytes());
    Some(packet)
}

fn pseudo_header(client: Ipv4Addr, length: u16) -> u32 {
    total_of(&dns::RESOLVER.octets())
        + total_of(&client.octets())
        + u32::from(PROTO_UDP)
        + u32::from(length)
}

fn total_of(bytes: &[u8]) -> u32 {
    let mut words = bytes.chunks_exact(2);
    let mut total: u32 = words
        .by_ref()
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    if let [tail] = words.remainder() {
        total += u32::from(u16::from_be_bytes([*tail, 0]));
    }
    total
}

fn checksum(mut total: u32) -> u16 {
    while total >> 16 != 0 {
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}

#[cfg(test)]
mod packet_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    const SUFFIX: &str = "nexguard";
    const MTU: usize = 1280;
    const CLIENT: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 7);
    const CLIENT_PORT: u16 = 41234;
    const PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    const QTYPE_A: u16 = 1;
    const QTYPE_AAAA: u16 = 28;
    const RCODE_MASK: u8 = 0x0f;
    const RCODE_NXDOMAIN: u8 = 3;

    struct Canned {
        response: Vec<u8>,
        seen: Arc<RwLock<Vec<Vec<u8>>>>,
    }

    impl Upstream for Canned {
        fn exchange(&self, query: &[u8]) -> Option<Vec<u8>> {
            self.seen.write().unwrap().push(query.to_vec());
            Some(self.response.clone())
        }
    }

    fn zone(names: &[(&str, Ipv4Addr)]) -> Zone {
        let peers: HashMap<String, Ipv4Addr> =
            names.iter().map(|(name, ip)| ((*name).to_owned(), *ip)).collect();
        Zone::new(SUFFIX, Arc::new(RwLock::new(peers)))
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&qtype.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message
    }

    fn request(destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = TTL;
        packet[9] = PROTO_UDP;
        packet[12..16].copy_from_slice(&CLIENT.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[IPV4_HEADER_LEN..IPV4_HEADER_LEN + 2].copy_from_slice(&CLIENT_PORT.to_be_bytes());
        packet[IPV4_HEADER_LEN + 2..IPV4_HEADER_LEN + 4].copy_from_slice(&DNS_PORT.to_be_bytes());
        let length = (UDP_HEADER_LEN + payload.len()) as u16;
        packet[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 6].copy_from_slice(&length.to_be_bytes());
        packet[IPV4_HEADER_LEN + UDP_HEADER_LEN..].copy_from_slice(payload);
        packet
    }

    fn awaited(resolver: &PacketDns) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Some(packet) = resolver.reply() {
                return packet;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the resolver never answered");
    }

    fn reply_payload(packet: &[u8]) -> Vec<u8> {
        assert_eq!(checksum(total_of(&packet[..IPV4_HEADER_LEN])), 0, "IPv4 checksum");
        let length = u16::from_be_bytes([packet[IPV4_HEADER_LEN + 4], packet[IPV4_HEADER_LEN + 5]]);
        assert_eq!(
            checksum(pseudo_header(CLIENT, length) + total_of(&packet[IPV4_HEADER_LEN..])),
            0,
            "UDP checksum"
        );
        assert_eq!(&packet[12..16], &dns::RESOLVER.octets());
        assert_eq!(&packet[16..20], &CLIENT.octets());
        assert_eq!(
            u16::from_be_bytes([packet[IPV4_HEADER_LEN], packet[IPV4_HEADER_LEN + 1]]),
            DNS_PORT
        );
        assert_eq!(
            u16::from_be_bytes([packet[IPV4_HEADER_LEN + 2], packet[IPV4_HEADER_LEN + 3]]),
            CLIENT_PORT
        );
        packet[IPV4_HEADER_LEN + UDP_HEADER_LEN..].to_vec()
    }

    #[test]
    fn a_peer_name_is_answered_with_a_packet_the_phone_can_read() {
        let resolver = PacketDns::new(zone(&[("laptop", PEER)]), None, MTU);
        let asked = query("laptop.nexguard", QTYPE_A);

        assert!(resolver.intercept(&request(dns::RESOLVER, &asked)));

        let response = reply_payload(&awaited(&resolver));
        assert_eq!(&response[..2], &asked[..2], "the query id is echoed");
        assert_eq!(response[2] & 0x80, 0x80, "the reply is marked as an answer");
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(&response[response.len() - 4..], &PEER.octets());
    }

    #[test]
    fn traffic_to_any_other_address_is_left_alone() {
        let resolver = PacketDns::new(zone(&[("laptop", PEER)]), None, MTU);
        let elsewhere = request(PEER, &query("laptop.nexguard", QTYPE_A));

        assert!(!resolver.intercept(&elsewhere));
        assert!(resolver.reply().is_none());
    }

    #[test]
    fn an_unknown_name_in_the_mesh_zone_does_not_reach_the_internet() {
        let seen = Arc::new(RwLock::new(Vec::new()));
        let upstream = Canned { response: vec![0xff; 12], seen: Arc::clone(&seen) };
        let resolver = PacketDns::new(zone(&[]), Some(Box::new(upstream)), MTU);

        assert!(resolver.intercept(&request(dns::RESOLVER, &query("ghost.nexguard", QTYPE_A))));

        let response = reply_payload(&awaited(&resolver));
        assert_eq!(response[3] & RCODE_MASK, RCODE_NXDOMAIN);
        assert!(seen.read().unwrap().is_empty(), "the mesh zone is never forwarded");
    }

    #[test]
    fn the_mesh_zone_answers_the_questions_it_has_no_record_for() {
        let seen = Arc::new(RwLock::new(Vec::new()));
        let upstream = Canned { response: vec![0xff; 12], seen: Arc::clone(&seen) };
        let resolver = PacketDns::new(zone(&[("laptop", PEER)]), Some(Box::new(upstream)), MTU);

        assert!(resolver.intercept(&request(dns::RESOLVER, &query("laptop.nexguard", QTYPE_AAAA))));

        let response = reply_payload(&awaited(&resolver));
        assert_eq!(response[3] & RCODE_MASK, RCODE_NXDOMAIN);
        assert!(seen.read().unwrap().is_empty(), "the mesh zone is never forwarded");
    }

    #[test]
    fn a_name_outside_the_mesh_is_forwarded_and_the_answer_comes_back() {
        let asked = query("example.com", QTYPE_A);
        let mut forwarded = asked.clone();
        forwarded[2] |= 0x80;
        forwarded.extend_from_slice(&[0xc0, 0x0c]);
        let seen = Arc::new(RwLock::new(Vec::new()));
        let upstream = Canned { response: forwarded.clone(), seen: Arc::clone(&seen) };
        let resolver = PacketDns::new(zone(&[("laptop", PEER)]), Some(Box::new(upstream)), MTU);

        assert!(resolver.intercept(&request(dns::RESOLVER, &asked)));

        assert_eq!(reply_payload(&awaited(&resolver)), forwarded);
        assert_eq!(seen.read().unwrap().as_slice(), &[asked]);
    }

    #[test]
    fn a_truncated_or_nonsense_packet_is_survived() {
        let resolver = PacketDns::new(zone(&[("laptop", PEER)]), None, MTU);
        let whole = request(dns::RESOLVER, &query("laptop.nexguard", QTYPE_A));

        for cut in 0..whole.len() {
            resolver.intercept(&whole[..cut]);
        }
        for byte in 0..=u8::MAX {
            resolver.intercept(&vec![byte; usize::from(byte)]);
        }
        let mut lying = whole.clone();
        lying[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 6].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(!resolver.intercept(&lying));

        assert!(resolver.intercept(&whole));
        assert!(!reply_payload(&awaited(&resolver)).is_empty());
    }
}
