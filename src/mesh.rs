use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::tun::TunDevice;

const PROBE_INTERVAL_SECS: u64 = 10;
const DIRECT_TIMEOUT_SECS: u64 = 30;

struct MeshTunnel {
    tunn: Tunn,
    endpoint: Option<SocketAddr>,
}

struct MeshPeerState {
    tunnel: Mutex<MeshTunnel>,
    allowed_ips: Vec<(u32, u32, u8)>,
    public_key_b64: String,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    direct_ok: AtomicBool,
    last_direct_rx: Mutex<Instant>,
    last_probe: Mutex<Instant>,
}

pub struct MeshManager {
    peers: Mutex<Vec<MeshPeerState>>,
    private_key: [u8; 32],
    udp: UdpSocket,
    active: AtomicBool,
}

impl MeshManager {
    pub fn new(private_key: [u8; 32], udp_port: u16) -> Self {
        let udp = UdpSocket::bind(format!("0.0.0.0:{}", udp_port))
            .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
            .expect("UDP bind failed");
        udp.set_nonblocking(true).ok();
        Self {
            peers: Mutex::new(Vec::new()),
            private_key,
            udp,
            active: AtomicBool::new(true),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn try_send(&self, packet: &[u8], dst_ip: u32) -> bool {
        if !self.is_active() { return false; }
        let peers = self.peers.lock().unwrap();
        for peer in peers.iter() {
            if !ip_matches(&peer.allowed_ips, dst_ip) { continue; }

            if peer.direct_ok.load(Ordering::Relaxed) {
                let mut tun = peer.tunnel.lock().unwrap();
                if let Some(ep) = tun.endpoint {
                    let mut buf = vec![0u8; packet.len() + 256];
                    if let TunnResult::WriteToNetwork(data) = tun.tunn.encapsulate(packet, &mut buf) {
                        if self.udp.send_to(data, ep).is_ok() {
                            peer.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                            return true;
                        }
                    }
                }
            }

            return false;
        }
        false
    }

    pub fn recv_and_process(&self, tun: &TunDevice) {
        if !self.is_active() { return; }
        let mut buf = [0u8; 65535];
        let mut dec = [0u8; 65535];
        while let Ok((n, from)) = self.udp.recv_from(&mut buf) {
            let peers = self.peers.lock().unwrap();
            for peer in peers.iter() {
                let mut t = peer.tunnel.lock().unwrap();
                match t.tunn.decapsulate(None, &buf[..n], &mut dec) {
                    TunnResult::WriteToTunnelV4(data, _) => {
                        let _ = tun.write_packet(data);
                        peer.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        if t.endpoint != Some(from) {
                            t.endpoint = Some(from);
                        }
                        peer.direct_ok.store(true, Ordering::Relaxed);
                        *peer.last_direct_rx.lock().unwrap() = Instant::now();
                        break;
                    }
                    TunnResult::WriteToNetwork(data) => {
                        let _ = self.udp.send_to(data, from);
                        peer.direct_ok.store(true, Ordering::Relaxed);
                        *peer.last_direct_rx.lock().unwrap() = Instant::now();
                        self.drain_handshake(&mut t, &mut dec, tun, from);
                        break;
                    }
                    _ => continue,
                }
            }
        }
    }

    fn drain_handshake(&self, t: &mut MeshTunnel, dec: &mut [u8], tun: &TunDevice, from: SocketAddr) {
        loop {
            match t.tunn.decapsulate(None, &[], dec) {
                TunnResult::WriteToNetwork(data) => { let _ = self.udp.send_to(data, from); }
                TunnResult::WriteToTunnelV4(data, _) => { let _ = tun.write_packet(data); break; }
                _ => break,
            }
        }
    }

    pub fn tick(&self) {
        if !self.is_active() { return; }
        let peers = self.peers.lock().unwrap();
        let mut buf = [0u8; 65535];
        let now = Instant::now();

        for peer in peers.iter() {
            let mut t = peer.tunnel.lock().unwrap();

            let last_rx = peer.last_direct_rx.lock().unwrap().elapsed().as_secs();
            if last_rx > DIRECT_TIMEOUT_SECS && peer.direct_ok.load(Ordering::Relaxed) {
                peer.direct_ok.store(false, Ordering::Relaxed);
                let _ = writeln!(std::io::stderr(), "[mesh] peer {} direct connection lost, using server relay",
                    &peer.public_key_b64[..8]);
            }

            let should_probe = peer.last_probe.lock().unwrap().elapsed().as_secs() >= PROBE_INTERVAL_SECS;
            if should_probe {
                *peer.last_probe.lock().unwrap() = now;
                if let TunnResult::WriteToNetwork(data) = t.tunn.update_timers(&mut buf) {
                    if let Some(ep) = t.endpoint {
                        let _ = self.udp.send_to(data, ep);
                    }
                }
            }
        }
    }

    pub fn peer_stats(&self) -> Vec<(String, bool, u64, u64)> {
        let peers = self.peers.lock().unwrap();
        peers.iter().map(|p| {
            (
                p.public_key_b64.clone(),
                p.direct_ok.load(Ordering::Relaxed),
                p.tx_bytes.load(Ordering::Relaxed),
                p.rx_bytes.load(Ordering::Relaxed),
            )
        }).collect()
    }

    pub fn update_peers(&self, mesh_peers: &[crate::api::MeshPeerInfo], my_pub_key: &str) {
        let mut peers = self.peers.lock().unwrap();

        for mp in mesh_peers {
            if mp.public_key == my_pub_key { continue; }

            let new_ep: Option<SocketAddr> = mp.endpoint.as_ref().and_then(|e| e.parse().ok());

            let found = peers.iter().any(|p| p.public_key_b64 == mp.public_key);
            if found {
                for p in peers.iter() {
                    if p.public_key_b64 == mp.public_key {
                        if let Some(ep) = new_ep {
                            let mut t = p.tunnel.lock().unwrap();
                            if t.endpoint.is_none() || t.endpoint != Some(ep) {
                                t.endpoint = Some(ep);
                                if !p.direct_ok.load(Ordering::Relaxed) {
                                    *p.last_probe.lock().unwrap() = Instant::now()
                                        - std::time::Duration::from_secs(PROBE_INTERVAL_SECS);
                                }
                            }
                        }
                        break;
                    }
                }
                continue;
            }

            let pub_key_bytes = match decode_b64_key(&mp.public_key) {
                Some(k) => k,
                None => continue,
            };
            let allowed_ips = parse_allowed_ips(&mp.allowed_ips);

            let secret = StaticSecret::from(self.private_key);
            let tunn = Tunn::new(secret, PublicKey::from(pub_key_bytes), None, Some(25), 0, None);
            let now = Instant::now();
            peers.push(MeshPeerState {
                tunnel: Mutex::new(MeshTunnel { tunn, endpoint: new_ep }),
                allowed_ips,
                public_key_b64: mp.public_key.clone(),
                tx_bytes: AtomicU64::new(0),
                rx_bytes: AtomicU64::new(0),
                direct_ok: AtomicBool::new(new_ep.is_some()),
                last_direct_rx: Mutex::new(now),
                last_probe: Mutex::new(now - std::time::Duration::from_secs(PROBE_INTERVAL_SECS)),
            });

            let _ = writeln!(std::io::stderr(), "[mesh] added peer {} endpoint={:?}",
                &mp.public_key[..8], new_ep);
        }
    }
}

fn ip_matches(allowed_ips: &[(u32, u32, u8)], dst_ip: u32) -> bool {
    for &(net, mask, _) in allowed_ips {
        if (dst_ip & mask) == net {
            return true;
        }
    }
    false
}

fn decode_b64_key(s: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()?;
    if bytes.len() != 32 { return None; }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn parse_allowed_ips(cidrs: &[String]) -> Vec<(u32, u32, u8)> {
    cidrs.iter().filter_map(|cidr| {
        let (ip_str, prefix_str) = cidr.split_once('/')?;
        let ip: std::net::Ipv4Addr = ip_str.parse().ok()?;
        let prefix: u8 = prefix_str.parse().ok()?;
        if prefix > 32 { return None; }
        let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
        let net = u32::from(ip) & mask;
        Some((net, mask, prefix))
    }).collect()
}
