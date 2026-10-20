use std::net::Ipv4Addr;

pub type Cidr = (u32, u32, u8);

pub const DEFAULT_ROUTE: Cidr = (0, 0, 0);
const PREFIX_MAX: u8 = 32;
const V4_HEADER_MIN: usize = 20;

pub fn parse(cidr: &str) -> Option<Cidr> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip_str.trim().parse().ok()?;
    let prefix: u8 = prefix_str.trim().parse().ok()?;
    if prefix > PREFIX_MAX {
        return None;
    }
    Some((u32::from(ip) & mask_of(prefix), mask_of(prefix), prefix))
}

pub fn host(ip: Ipv4Addr) -> Cidr {
    (u32::from(ip), u32::MAX, PREFIX_MAX)
}

pub fn network(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    parse(cidr).map(|(net, _, prefix)| (Ipv4Addr::from(net), prefix))
}

pub fn best_prefix(allowed: &[Cidr], dst: u32) -> Option<u8> {
    allowed
        .iter()
        .filter(|&&(net, mask, _)| (dst & mask) == net)
        .map(|&(_, _, prefix)| prefix)
        .max()
}

pub fn contains(allowed: &[Cidr], ip: u32) -> bool {
    best_prefix(allowed, ip).is_some()
}

/// The source address of an IPv4 packet, or None for anything that is not one.
pub fn source_v4(packet: &[u8]) -> Option<u32> {
    if packet.len() < V4_HEADER_MIN || packet[0] >> 4 != 4 {
        return None;
    }
    Some(u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]))
}

/// Inbound cryptokey routing: a peer may only send from an address its own
/// allowed table covers, and never from one that routes more specifically to
/// someone else, so even the exit node, which covers everything, cannot speak
/// for another device.
pub fn permits_v4(own: &[Cidr], foreign: &[Cidr], packet: &[u8]) -> bool {
    let Some(src) = source_v4(packet) else {
        return false;
    };
    match (best_prefix(own, src), best_prefix(foreign, src)) {
        (Some(mine), Some(theirs)) => mine >= theirs,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Only the exit node this machine selected carries the default route, and it
/// is the one peer whose traffic may come from anywhere.
pub fn is_exit(allowed: &[Cidr]) -> bool {
    allowed.contains(&DEFAULT_ROUTE)
}

fn mask_of(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (PREFIX_MAX - prefix)
    }
}
