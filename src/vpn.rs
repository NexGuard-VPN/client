use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;

use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::{api, dns, mesh, route, stun, tun, wg};

pub struct VpnConfig {
    pub server: String,
    pub token: String,
    pub name: String,
    pub control_port: u16,
    pub listen_port: u16,
    pub mtu: usize,
    pub vpn_network: Option<String>,
    pub internet: bool,
    pub relay: Option<String>,
    pub relay_name: Option<String>,
    pub join_url: Option<String>,
    pub share_lan: bool,
    pub kill_switch: bool,
    pub dns_leak_protection: bool,
    pub extra_routes: Vec<String>,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            token: String::new(),
            name: String::new(),
            control_port: 9190,
            listen_port: 0,
            mtu: 1420,
            vpn_network: None,
            internet: false,
            relay: None,
            relay_name: None,
            join_url: None,
            share_lan: false,
            kill_switch: false,
            dns_leak_protection: false,
            extra_routes: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct VpnStatus {
    pub tx: Arc<AtomicU64>,
    pub rx: Arc<AtomicU64>,
    pub connected_at: u64,
    pub address: String,
    #[allow(dead_code)]
    pub address_v6: Option<String>,
    pub server: String,
    pub endpoint: String,
    pub control_port: u16,
    pub tun_name: String,
    pub internet_mode: bool,
    pub geo: Arc<Mutex<Option<api::GeoInfo>>>,
    pub connection_dropped: Arc<AtomicBool>,
    /// Address whose host route bypasses the tunnel (relay, or the server in
    /// direct mode) — the right probe target for network-change detection.
    pub net_target: String,
    pub peers: Arc<Mutex<Vec<PeerView>>>,
}

/// One device on the mesh, as shown in the UI.
#[derive(Clone)]
pub struct PeerView {
    pub key: String,
    pub name: String,
    pub ip: String,
    pub direct: bool,
}

fn build_peer_views(
    peers: &[api::MeshPeerInfo],
    mgr: Option<&Arc<mesh::MeshManager>>,
) -> Vec<PeerView> {
    let direct_by_key: HashMap<String, bool> = mgr
        .map(|m| {
            m.peer_stats()
                .into_iter()
                .map(|(key, direct, _, _)| (key, direct))
                .collect()
        })
        .unwrap_or_default();
    let mut views: Vec<PeerView> = peers
        .iter()
        .map(|p| PeerView {
            key: p.public_key.clone(),
            name: if p.name.is_empty() {
                p.public_key.chars().take(8).collect()
            } else {
                p.name.clone()
            },
            ip: p
                .allowed_ips
                .first()
                .map(|c| c.split('/').next().unwrap_or(c).to_string())
                .unwrap_or_default(),
            direct: direct_by_key.get(&p.public_key).copied().unwrap_or(false),
        })
        .collect();
    views.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    views
}

fn try_b64_decode(s: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("invalid base64: {}", e))?;
    if b.len() < 32 {
        return Err(format!("key too short: {} bytes", b.len()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&b[..32]);
    Ok(k)
}

fn try_parse_cidr(s: &str) -> Result<(Ipv4Addr, u8), String> {
    let (ip_str, prefix_str) = s.split_once('/')
        .ok_or_else(|| format!("invalid CIDR: {}", s))?;
    let ip: Ipv4Addr = ip_str.parse()
        .map_err(|e| format!("invalid IP '{}': {}", ip_str, e))?;
    let prefix: u8 = prefix_str.parse()
        .map_err(|e| format!("invalid prefix '{}': {}", prefix_str, e))?;
    Ok((ip, prefix))
}

pub fn connect(
    config: VpnConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<VpnStatus, String> {
    let private_key = crate::load_or_generate_key();
    let secret = StaticSecret::from(private_key);
    let public_key = PublicKey::from(&secret);
    let pub_key_b64 = crate::b64_encode(public_key.as_bytes());

    let mut client_name = config.name.clone();
    if client_name.is_empty() {
        client_name = crate::generate_client_name();
    }

    let mut advertise_routes: Vec<String> = if config.share_lan {
        crate::route::detect_local_subnets()
    } else {
        Vec::new()
    };
    advertise_routes.extend(config.extra_routes.iter().cloned());

    let cached_join: Option<api::JoinResponse> = crate::cache::load(&config.token)
        .and_then(|e| {
            if e.join_response.is_null() { return None; }
            serde_json::from_value::<api::JoinResponse>(e.join_response).ok()
        });

    let join_resp = if let Some(jr) = cached_join {
        jr
    } else {
        let fresh = if let Some(ref url) = config.join_url {
            api::join_via_api_with_routes(url, &config.token, &pub_key_b64, &client_name, &advertise_routes)?
        } else {
            api::try_join_server_with_routes(
                &config.server,
                config.control_port,
                &config.token,
                &pub_key_b64,
                &client_name,
                &advertise_routes,
            )?
        };
        if let Ok(jr_val) = serde_json::to_value(&fresh) {
            let existing = crate::cache::load(&config.token);
            crate::cache::save(
                &config.token,
                existing.as_ref().and_then(|e| e.server.clone()),
                existing.as_ref().and_then(|e| e.relay.clone()),
                existing.as_ref().and_then(|e| e.relay_name.clone()),
                existing.as_ref().and_then(|e| e.join_url.clone()),
                jr_val,
            );
        }
        fresh
    };

    let assigned_addr = join_resp.address.clone();
    let server_pub_key = try_b64_decode(&join_resp.server_public_key)?;

    let (ip, prefix) = try_parse_cidr(&assigned_addr)?;
    let server_endpoint = if let Some(ref ep) = join_resp.server_endpoint {
        ep.parse().unwrap_or_else(|_| {
            api::try_parse_endpoint(&config.server).unwrap_or_else(|_| {
                std::net::SocketAddr::new(
                    config.server.parse().unwrap_or(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    51820,
                )
            })
        })
    } else {
        api::try_parse_endpoint(&config.server)
            .map_err(|e| format!("endpoint: {}", e))?
    };

    let tun_dev = tun::TunDevice::try_create(config.mtu)?;
    tun_dev.set_address(ip, prefix);

    if let Some(ref v6) = join_resp.address_v6 {
        if let Some((v6_ip, v6_prefix)) = crate::parse_ipv6_cidr(v6) {
            tun_dev.set_address_v6(&v6_ip.to_string(), v6_prefix);
        }
    }

    tun_dev.set_up();

    if !config.internet {
        if prefix < 32 {
            let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
            let net = Ipv4Addr::from(u32::from(ip) & mask);
            let _ = route::add_route(net, prefix, tun_dev.name());
        }

        for peer in &join_resp.peers {
            if let Some(ips) = peer.get("allowed_ips").and_then(|v| v.as_array()) {
                for cidr_val in ips {
                    if let Some(cidr) = cidr_val.as_str() {
                        if let Ok((net_ip, net_prefix)) = try_parse_cidr(cidr) {
                            if net_ip != ip {
                                let _ = route::add_route(net_ip, net_prefix, tun_dev.name());
                            }
                        }
                    }
                }
            }
        }

        if let Some(ref network) = config.vpn_network {
            if let Ok((net_ip, net_prefix)) = try_parse_cidr(network) {
                let _ = route::add_route(net_ip, net_prefix, tun_dev.name());
            }
        }
    }

    let exit_state = if config.internet {
        let wg_ip = server_endpoint.ip().to_string();
        let control_ip = {
            use std::net::ToSocketAddrs;
            let target = if config.server.contains(':') {
                config.server.clone()
            } else {
                format!("{}:9190", config.server)
            };
            target.to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next())
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|| wg_ip.clone())
        };
        let relay_ip = config.relay.as_ref()
            .and_then(|rs| rs.split(':').next().map(|s: &str| s.to_string()));
        let mut preserve_ips: Vec<&str> = vec![&wg_ip];
        if control_ip != wg_ip {
            preserve_ips.push(&control_ip);
        }
        if let Some(ref rip) = relay_ip {
            if rip != &wg_ip && rip != &control_ip {
                preserve_ips.push(rip);
            }
        }
        let has_v6 = join_resp.vpn_network_v6.is_some();
        match route::ExitRouteState::setup_dual(&preserve_ips, tun_dev.name(), has_v6) {
            Ok(state) => Some(state),
            Err(e) => return Err(format!("internet setup failed: {}", e)),
        }
    } else {
        None
    };

    let relay_name = config.relay_name.clone();

    let server_pub = PublicKey::from(server_pub_key);
    let keepalive = crate::jittered_keepalive();
    let tunn = Tunn::new(secret, server_pub, None, Some(keepalive), 0, None);
    let tunnel = Mutex::new(wg::WgState { tunn, server_pub_key: server_pub });

    let tx = Arc::new(AtomicU64::new(0));
    let rx = Arc::new(AtomicU64::new(0));

    let geo: Arc<Mutex<Option<api::GeoInfo>>> = Arc::new(Mutex::new(None));
    let connection_dropped = Arc::new(AtomicBool::new(false));
    let peer_views: Arc<Mutex<Vec<PeerView>>> = Arc::new(Mutex::new(Vec::new()));

    let status = VpnStatus {
        tx: Arc::clone(&tx),
        rx: Arc::clone(&rx),
        connected_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        address: assigned_addr,
        address_v6: join_resp.address_v6.clone(),
        server: config.server.clone(),
        endpoint: server_endpoint.to_string(),
        control_port: config.control_port,
        tun_name: tun_dev.name().to_string(),
        internet_mode: config.internet,
        geo,
        connection_dropped: Arc::clone(&connection_dropped),
        net_target: match config.relay.as_deref() {
            Some(r) if !r.is_empty() => r.split(',').next().unwrap_or(r).trim().to_string(),
            _ => server_endpoint.to_string(),
        },
        peers: Arc::clone(&peer_views),
    };

    let dns_peer_map: Arc<RwLock<HashMap<String, Ipv4Addr>>> = Arc::new(RwLock::new(HashMap::new()));

    let mesh_mgr = if join_resp.mesh.unwrap_or(false) {
        let mesh_port = config.listen_port.wrapping_add(1);
        let mgr = Arc::new(mesh::MeshManager::new(private_key, mesh_port));
        if let Some(ref peers) = join_resp.mesh_peers {
            let parsed = api::parse_mesh_peers(peers);
            let map = dns::extract_peer_map(&parsed);
            *dns_peer_map.write().unwrap() = map;
            mgr.update_peers(&parsed, &pub_key_b64);
            *peer_views.lock().unwrap() = build_peer_views(&parsed, Some(&mgr));
        }

        let refresh_mgr = Arc::clone(&mgr);
        let refresh_server = config.server.clone();
        let refresh_port = config.control_port;
        let refresh_token = config.token.clone();
        let refresh_pub_key = pub_key_b64.clone();
        let shutdown_ref = Arc::clone(&shutdown);
        let dns_map_ref = Arc::clone(&dns_peer_map);
        let views_ref = Arc::clone(&peer_views);
        std::thread::spawn(move || {
            // Peer directory refreshes on a slow tick; direct/relay state flips
            // fast, so it is re-read every few seconds in between.
            let directory_every = 10;
            let mut tick: u32 = 0;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3));
                if shutdown_ref.load(Ordering::Relaxed) { break; }
                if tick % directory_every == 0 {
                    let peers = api::get_mesh_peers(&refresh_server, refresh_port, &refresh_token);
                    if !peers.is_empty() {
                        let map = dns::extract_peer_map(&peers);
                        *dns_map_ref.write().unwrap() = map;
                        refresh_mgr.update_peers(&peers, &refresh_pub_key);
                        *views_ref.lock().unwrap() = build_peer_views(&peers, Some(&refresh_mgr));
                    }
                } else {
                    let direct: HashMap<String, bool> = refresh_mgr
                        .peer_stats()
                        .into_iter()
                        .map(|(k, d, _, _)| (k, d))
                        .collect();
                    let mut views = views_ref.lock().unwrap();
                    for v in views.iter_mut() {
                        if let Some(d) = direct.get(&v.key) {
                            v.direct = *d;
                        }
                    }
                }
                tick = tick.wrapping_add(1);
            }
        });
        Some(mgr)
    } else {
        None
    };

    let dns_guard = if mesh_mgr.is_some() || config.dns_leak_protection {
        let upstream = std::env::var("NEXGUARD_DNS_UPSTREAM")
            .unwrap_or_else(|_| "1.1.1.1".to_string());
        if let Some(resolver) = dns::DnsResolver::try_start(&upstream, Arc::clone(&dns_peer_map)) {
            let shutdown_ref = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                resolver.run_with_shutdown(&shutdown_ref);
            });
        }

        let _ = route::add_route(Ipv4Addr::new(100, 100, 100, 100), 32, tun_dev.name());

        let nat_mgr = mesh_mgr.clone();
        let nat_server = config.server.clone();
        let nat_port = config.control_port;
        let nat_token = config.token.clone();
        let nat_pub_key = pub_key_b64.clone();
        let nat_shutdown = Arc::clone(&shutdown);
        std::thread::spawn(move || {
            let interval = std::time::Duration::from_secs(300);
            loop {
                if nat_shutdown.load(Ordering::Relaxed) { break; }
                if let Some(ref mgr) = nat_mgr {
                    let local_port = mgr.local_port();
                    if local_port > 0 {
                        if let Some(ep) = stun::discover_public_endpoint_on_port(local_port) {
                            let _ = api::report_endpoint(&nat_server, nat_port, &nat_token, &nat_pub_key, &ep.to_string());
                        }
                    }
                }
                std::thread::sleep(interval);
            }
        });

        route::set_system_dns(crate::dns::MAGIC_DNS_IP)
    } else {
        None
    };

    let relay_addr = config.relay.clone().unwrap_or_default();
    let server_for_relay = config.server.clone();
    let token_for_relay = config.token.clone();

    let kill_switch = if config.kill_switch {
        let server_ip = server_endpoint.ip().to_string();
        Some(route::KillSwitch::activate(tun_dev.name(), &[&server_ip]))
    } else {
        None
    };

    let shutdown_dp = Arc::clone(&shutdown);
    let rx_for_check = Arc::clone(&rx);
    let token_for_cache = config.token.clone();

    if relay_addr.is_empty() {
        let direct_endpoint = server_endpoint;
        let mesh_for_direct = mesh_mgr.clone();
        let dropped_flag = Arc::clone(&connection_dropped);
        std::thread::spawn(move || {
            match std::net::UdpSocket::bind("0.0.0.0:0") {
                Ok(udp) => {
                    let _ = udp.set_read_timeout(Some(std::time::Duration::from_millis(50)));
                    wg::run_data_plane_udp(
                        &tun_dev, &udp, direct_endpoint, &tunnel, &tx, &rx, &shutdown_dp,
                        mesh_for_direct.as_ref().map(|m| m.as_ref()),
                    );
                    if rx_for_check.load(Ordering::Relaxed) == 0 {
                        crate::cache::invalidate(&token_for_cache);
                    }
                }
                Err(e) => {
                    let _ = writeln!(std::io::stderr(), "[vpn-client] udp bind failed: {}", e);
                    crate::cache::invalidate(&token_for_cache);
                }
            }
            if !shutdown_dp.load(Ordering::Relaxed) {
                dropped_flag.store(true, Ordering::Relaxed);
            }
            drop(exit_state);
            drop(mesh_mgr);
            drop(kill_switch);
            drop(dns_guard);
        });
        return Ok(status);
    }

    let dropped_flag = Arc::clone(&connection_dropped);
    std::thread::spawn(move || {
        let target = relay_name.as_deref().unwrap_or(&server_for_relay);
        match wg::connect_relay(&relay_addr, target, &token_for_relay) {
            Ok(mut stream) => {
                wg::run_data_plane_tls(
                    &tun_dev, &mut stream, &tunnel, &tx, &rx, &shutdown_dp,
                    mesh_mgr.as_ref().map(|m| m.as_ref()), None,
                );
                if rx_for_check.load(Ordering::Relaxed) == 0 {
                    crate::cache::invalidate(&token_for_cache);
                }
            }
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "[vpn-client] connection failed: {}", e);
                crate::cache::invalidate(&token_for_cache);
            }
        }
        drop(exit_state);
        drop(mesh_mgr);
        drop(kill_switch);
        drop(dns_guard);
        if !shutdown_dp.load(Ordering::Relaxed) {
            dropped_flag.store(true, Ordering::Relaxed);
        }
    });

    Ok(status)
}
