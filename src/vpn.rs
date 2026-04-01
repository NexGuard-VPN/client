use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::{api, mesh, route, tun, wg};

pub struct VpnConfig {
    pub server: String,
    pub token: String,
    pub name: String,
    pub control_port: u16,
    pub listen_port: u16,
    pub mtu: usize,
    pub vpn_network: Option<String>,
    pub internet: bool,
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
        }
    }
}

#[derive(Clone)]
pub struct VpnStatus {
    pub tx: Arc<AtomicU64>,
    pub rx: Arc<AtomicU64>,
    pub connected_at: u64,
    pub address: String,
    pub address_v6: Option<String>,
    pub server: String,
    pub endpoint: String,
    pub tun_name: String,
    pub internet_mode: bool,
    pub geo: Arc<Mutex<Option<api::GeoInfo>>>,
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
    let private_key = crate::generate_private_key();
    let secret = StaticSecret::from(private_key);
    let public_key = PublicKey::from(&secret);
    let pub_key_b64 = crate::b64_encode(public_key.as_bytes());

    let mut client_name = config.name.clone();
    if client_name.is_empty() {
        client_name = crate::generate_client_name();
    }

    let join_resp = api::try_join_server(
        &config.server,
        config.control_port,
        &config.token,
        &pub_key_b64,
        &client_name,
    )?;

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
        let mut preserve_ips: Vec<&str> = vec![&wg_ip];
        if control_ip != wg_ip {
            preserve_ips.push(&control_ip);
        }
        let vpn_net = join_resp.vpn_network.as_deref()
            .or(config.vpn_network.as_deref());
        let has_v6 = join_resp.vpn_network_v6.is_some();
        match route::ExitRouteState::setup_dual(&preserve_ips, tun_dev.name(), vpn_net, has_v6) {
            Ok(state) => Some(state),
            Err(e) => return Err(format!("internet setup failed: {}", e)),
        }
    } else {
        None
    };

    let udp = UdpSocket::bind(format!("0.0.0.0:{}", config.listen_port))
        .map_err(|e| format!("UDP bind: {}", e))?;
    udp.set_nonblocking(true).ok();

    let tunn = Tunn::new(secret, PublicKey::from(server_pub_key), None, Some(25), 0, None);
    let tunnel = Mutex::new(wg::WgState {
        tunn,
        endpoint: server_endpoint,
    });

    let tx = Arc::new(AtomicU64::new(0));
    let rx = Arc::new(AtomicU64::new(0));

    let geo: Arc<Mutex<Option<api::GeoInfo>>> = Arc::new(Mutex::new(None));

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
        tun_name: tun_dev.name().to_string(),
        internet_mode: config.internet,
        geo,
    };

    let mesh_mgr = if join_resp.mesh.unwrap_or(false) {
        let mesh_port = config.listen_port.wrapping_add(1);
        let mgr = Arc::new(mesh::MeshManager::new(private_key, mesh_port));
        if let Some(ref peers) = join_resp.mesh_peers {
            let parsed = api::parse_mesh_peers(peers);
            mgr.update_peers(&parsed, &pub_key_b64);
        }

        let refresh_mgr = Arc::clone(&mgr);
        let refresh_server = config.server.clone();
        let refresh_port = config.control_port;
        let refresh_token = config.token.clone();
        let refresh_pub_key = pub_key_b64.clone();
        let shutdown_ref = Arc::clone(&shutdown);
        std::thread::spawn(move || {
            let interval = std::time::Duration::from_secs(30);
            loop {
                std::thread::sleep(interval);
                if shutdown_ref.load(Ordering::Relaxed) { break; }
                let peers = api::get_mesh_peers(&refresh_server, refresh_port, &refresh_token);
                refresh_mgr.update_peers(&peers, &refresh_pub_key);
            }
        });
        Some(mgr)
    } else {
        None
    };

    let shutdown_dp = Arc::clone(&shutdown);
    std::thread::spawn(move || {
        wg::run_data_plane(
            &tun_dev, &udp, &tunnel, &tx, &rx, &shutdown_dp,
            mesh_mgr.as_ref().map(|m| m.as_ref()),
        );
        drop(exit_state);
        drop(mesh_mgr);
    });

    Ok(status)
}
