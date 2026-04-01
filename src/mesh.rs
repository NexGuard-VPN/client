use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::net::{SocketAddr, UdpSocket};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::tun::TunDevice;

struct MeshTunnel {
    tunn: Tunn,
    endpoint: Option<SocketAddr>,
}

struct MeshPeerState {
    tunnel: Mutex<MeshTunnel>,
    allowed_ips: Vec<(u32, u32, u8)>,
    #[allow(dead_code)]
    public_key_b64: String,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
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

    pub fn add_peer(&self, public_key: &[u8; 32], endpoint: Option<SocketAddr>, allowed_ips: Vec<(u32, u32, u8)>, pub_key_b64: String) {
        let secret = StaticSecret::from(self.private_key);
        let tunn = Tunn::new(secret, PublicKey::from(*public_key), None, Some(25), 0, None);
        let state = MeshPeerState {
            tunnel: Mutex::new(MeshTunnel { tunn, endpoint }),
            allowed_ips,
            public_key_b64: pub_key_b64,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        };
        self.peers.lock().unwrap().push(state);
    }

    pub fn try_send(&self, packet: &[u8], dst_ip: u32) -> bool {
        if !self.is_active() { return false; }
        let peers = self.peers.lock().unwrap();
        for peer in peers.iter() {
            if !ip_matches(&peer.allowed_ips, dst_ip) { continue; }
            let mut tun = peer.tunnel.lock().unwrap();
            let endpoint = match tun.endpoint {
                Some(ep) => ep,
                None => return false,
            };
            let mut buf = vec![0u8; packet.len() + 256];
            if let TunnResult::WriteToNetwork(data) = tun.tunn.encapsulate(packet, &mut buf) {
                if self.udp.send_to(data, endpoint).is_ok() {
                    peer.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                    return true;
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
                        break;
                    }
                    TunnResult::WriteToNetwork(data) => {
                        let _ = self.udp.send_to(data, from);
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
        for peer in peers.iter() {
            let mut t = peer.tunnel.lock().unwrap();
            if let TunnResult::WriteToNetwork(data) = t.tunn.update_timers(&mut buf) {
                if let Some(ep) = t.endpoint {
                    let _ = self.udp.send_to(data, ep);
                }
            }
        }
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
                            if t.endpoint != Some(ep) {
                                t.endpoint = Some(ep);
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
            peers.push(MeshPeerState {
                tunnel: Mutex::new(MeshTunnel { tunn, endpoint: new_ep }),
                allowed_ips,
                public_key_b64: mp.public_key.clone(),
                tx_bytes: AtomicU64::new(0),
                rx_bytes: AtomicU64::new(0),
            });
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
