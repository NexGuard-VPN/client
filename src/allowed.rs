use std::net::Ipv4Addr;

pub type Cidr = (u32, u32, u8);

pub const DEFAULT_ROUTE: Cidr = (0, 0, 0);
const PREFIX_MAX: u8 = 32;

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

fn mask_of(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (PREFIX_MAX - prefix)
    }
}
