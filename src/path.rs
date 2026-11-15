use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// What is known about one way of reaching a peer.
pub struct PathSample {
    pub addr: SocketAddr,
    pub lan: bool,
    pub rtt: Option<Duration>,
    pub last_pong: Option<Instant>,
    pub last_data: Option<Instant>,
}

/// Picks the address to send to. A path disco has measured wins, preferring the
/// LAN and then the lower round trip. Failing that, a peer whose packets are
/// arriving is reachable whatever it advertised, so the address they came from
/// wins over one that has only ever been claimed.
pub fn choose(samples: &[PathSample], now: Instant, fresh: Duration) -> Option<SocketAddr> {
    let mut best: Option<(&PathSample, Duration)> = None;
    for sample in samples {
        let (pong, rtt) = match (sample.last_pong, sample.rtt) {
            (Some(pong), Some(rtt)) => (pong, rtt),
            _ => continue,
        };
        if now.duration_since(pong) > fresh {
            continue;
        }
        let better = match best {
            None => true,
            Some((current, current_rtt)) => {
                (sample.lan && !current.lan) || (sample.lan == current.lan && rtt < current_rtt)
            }
        };
        if better {
            best = Some((sample, rtt));
        }
    }
    if let Some((sample, _)) = best {
        return Some(sample.addr);
    }
    samples
        .iter()
        .filter_map(|s| s.last_data.map(|seen| (s.addr, seen)))
        .filter(|(_, seen)| now.duration_since(*seen) <= fresh)
        .max_by_key(|(_, seen)| *seen)
        .map(|(addr, _)| addr)
}

/// One peer's claim on an address, with when that address last proved it
/// belongs to the peer.
pub struct AddressClaim {
    pub addr: SocketAddr,
    pub owner: usize,
    pub seen: Option<Instant>,
}

/// Which peer an address is believed to belong to. Peers behind one NAT share a
/// public IP and the NAT hands their ports around, so an address can be claimed
/// by more than one peer; the claim proven most recently wins.
pub fn owners(mut claims: Vec<AddressClaim>) -> HashMap<SocketAddr, usize> {
    claims.sort_by_key(|claim| claim.seen);
    claims.into_iter().map(|claim| (claim.addr, claim.owner)).collect()
}

/// The order to try peers in for a packet that is not disco or STUN: the peer
/// the address is believed to belong to first, then every other one, because
/// that belief goes stale whenever a NAT reassigns the port.
pub fn trial_order(hint: Option<usize>, count: usize) -> impl Iterator<Item = usize> {
    hint.filter(|&idx| idx < count)
        .into_iter()
        .chain((0..count).filter(move |&idx| Some(idx) != hint))
}

/// The address a peer's traffic appears to come from. Endpoints also carry the
/// peer's own LAN and mesh addresses, which say nothing about the internet, so
/// only a routable public address counts.
pub fn public_ip(endpoints: &[String]) -> Option<String> {
    endpoints
        .iter()
        .filter_map(|endpoint| endpoint.parse::<SocketAddr>().ok())
        .map(|addr| addr.ip())
        .find(|ip| is_public(ip))
        .map(|ip| ip.to_string())
}

fn is_public(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                // 100.64.0.0/10 is the carrier-grade range the mesh itself uses
                && !(v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        std::net::IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    }
}
