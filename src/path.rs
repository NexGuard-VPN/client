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
