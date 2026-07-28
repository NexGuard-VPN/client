use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::{api, mesh, route, tun, wg};

const HTTPS_PORT: u16 = 443;
const DNS_ENV: &str = "NEXGUARD_DNS";
const HTTPS_PREFIX: &str = "https://";
const API_HOST_ENV: &str = "NEXGUARD_API_HOST";
const DEFAULT_API_HOST: &str = "api.nexguard.sh";
const INITIAL_BACKOFF_MS: u64 = 1000;
const MAX_BACKOFF_MS: u64 = 30_000;
const BACKOFF_TICK_MS: u64 = 100;
const MAX_FAILED_HANDSHAKES: u32 = 2;
const HANDSHAKE_FAILED_MSG: &str = "Handshake failed. Check your token or server.";
const TERMINAL_ERROR_MARKERS: &[&str] = &[
    "401",
    "403",
    "unauthorized",
    "forbidden",
    "invalid token",
    "invalid base64",
    "key too short",
    "invalid cidr",
    "invalid ip",
    "invalid prefix",
    "no relay address configured",
];

pub fn api_host() -> String {
    std::env::var(API_HOST_ENV).unwrap_or_else(|_| DEFAULT_API_HOST.to_string())
}

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
    pub kill_switch: Arc<AtomicBool>,
    pub dns: Vec<String>,
}

pub fn resolve_dns_servers(from_server: Option<&serde_json::Value>, configured: &[String]) -> Vec<String> {
    let provided = api::parse_dns_servers(from_server);
    if !provided.is_empty() {
        return provided;
    }
    if !configured.is_empty() {
        return api::parse_dns_servers(Some(&serde_json::Value::from(configured.to_vec())));
    }
    match std::env::var(DNS_ENV) {
        Ok(value) => api::parse_dns_servers(Some(&serde_json::Value::from(value))),
        Err(_) => Vec::new(),
    }
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
            kill_switch: Arc::new(AtomicBool::new(false)),
            dns: Vec::new(),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Handshaking,
    Connected,
    Degraded,
    Reconnecting,
    Error(String),
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
    pub tun_name: String,
    pub internet_mode: bool,
    pub dns_protected: bool,
    pub geo: Arc<Mutex<Option<api::GeoInfo>>>,
    pub geo_failed: Arc<AtomicBool>,
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

struct SessionShared {
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
    geo: Arc<Mutex<Option<api::GeoInfo>>>,
    geo_failed: Arc<AtomicBool>,
    connected_at: u64,
    state: Arc<Mutex<ConnectionState>>,
    status_slot: Arc<Mutex<Option<VpnStatus>>>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn set_state(state: &Arc<Mutex<ConnectionState>>, value: ConnectionState) {
    *state.lock().unwrap() = value;
}

fn push_resolved(set: &mut Vec<String>, host: &str, default_port: u16) {
    use std::net::ToSocketAddrs;
    let target = if host.contains(':') { host.to_string() } else { format!("{}:{}", host, default_port) };
    if let Ok(addrs) = target.to_socket_addrs() {
        for a in addrs {
            if !a.ip().is_loopback() && !a.ip().is_unspecified() {
                set.push(a.ip().to_string());
            }
        }
    }
}

pub fn kill_switch_allow_ips(
    endpoint_ip: Option<std::net::IpAddr>,
    server: &str,
    control_port: u16,
    relay: Option<&str>,
    join_url: Option<&str>,
) -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();
    if let Some(ip) = endpoint_ip {
        if !ip.is_loopback() && !ip.is_unspecified() {
            ips.push(ip.to_string());
        }
    }
    push_resolved(&mut ips, server, control_port);
    if let Some(relays) = relay {
        for addr in relays.split(',') {
            push_resolved(&mut ips, addr.trim(), HTTPS_PORT);
        }
    }
    if let Some(url) = join_url {
        if let Some(host) = url.strip_prefix(HTTPS_PREFIX).and_then(|s| s.split('/').next()) {
            push_resolved(&mut ips, host, HTTPS_PORT);
        }
    }
    push_resolved(&mut ips, &api_host(), HTTPS_PORT);
    ips.sort();
    ips.dedup();
    ips
}

fn is_terminal_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    TERMINAL_ERROR_MARKERS.iter().any(|m| lower.contains(m))
}

struct SessionLinks {
    kill_switch: Option<route::KillSwitch>,
    dns: Option<route::DnsState>,
    exit_state: Option<route::ExitRouteState>,
    tun: tun::TunDevice,
    address: String,
    registered: bool,
}

impl SessionLinks {
    fn sync_kill_switch(&mut self, config: &VpnConfig, server_endpoint: &std::net::SocketAddr) {
        let wanted = config.kill_switch.load(Ordering::Relaxed);
        if !wanted {
            self.kill_switch = None;
            return;
        }
        if self.kill_switch.is_some() {
            return;
        }
        if !self.registered {
            route::register_active_tun(self.tun.name());
            self.registered = true;
        }
        let allow_ips = kill_switch_allow_ips(
            Some(server_endpoint.ip()),
            &config.server,
            config.control_port,
            config.relay.as_deref(),
            config.join_url.as_deref(),
        );
        let refs: Vec<&str> = allow_ips.iter().map(|s| s.as_str()).collect();
        self.kill_switch = Some(route::KillSwitch::activate(self.tun.name(), &refs));
    }
}

impl Drop for SessionLinks {
    fn drop(&mut self) {
        if self.registered {
            route::unregister_active_tun(self.tun.name());
        }
    }
}

pub fn run_session(
    config: VpnConfig,
    shutdown: Arc<AtomicBool>,
    state: Arc<Mutex<ConnectionState>>,
    status_slot: Arc<Mutex<Option<VpnStatus>>>,
    last_error: Arc<Mutex<Option<String>>>,
) {
    let shared = SessionShared {
        tx: Arc::new(AtomicU64::new(0)),
        rx: Arc::new(AtomicU64::new(0)),
        geo: Arc::new(Mutex::new(None)),
        geo_failed: Arc::new(AtomicBool::new(false)),
        connected_at: now_secs(),
        state: Arc::clone(&state),
        status_slot: Arc::clone(&status_slot),
    };

    {
        let geo = Arc::clone(&shared.geo);
        let geo_failed = Arc::clone(&shared.geo_failed);
        let rx = Arc::clone(&shared.rx);
        let sd = Arc::clone(&shutdown);
        std::thread::spawn(move || {
            let mut waited = 0;
            while rx.load(Ordering::Relaxed) == 0 && !sd.load(Ordering::Relaxed) && waited < 240 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                waited += 1;
            }
            if sd.load(Ordering::Relaxed) { return; }
            let mut delay = 1000u64;
            for _ in 0..5 {
                if sd.load(Ordering::Relaxed) { return; }
                if let Some(info) = api::fetch_geo_info() {
                    *geo.lock().unwrap() = Some(info);
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(delay));
                delay = (delay * 2).min(8000);
            }
            geo_failed.store(true, Ordering::Relaxed);
        });
    }

    let mut links: Option<SessionLinks> = None;
    let mut backoff_ms: u64 = INITIAL_BACKOFF_MS;
    let mut first = true;
    let mut failed_handshakes = 0u32;

    loop {
        if shutdown.load(Ordering::Relaxed) { break; }
        set_state(&shared.state, if first { ConnectionState::Connecting } else { ConnectionState::Reconnecting });
        first = false;

        match run_attempt(&config, &shutdown, &shared, &mut links) {
            Ok(true) => {
                backoff_ms = INITIAL_BACKOFF_MS;
                failed_handshakes = 0;
                *last_error.lock().unwrap() = None;
            }
            Ok(false) => {
                failed_handshakes += 1;
                if failed_handshakes >= MAX_FAILED_HANDSHAKES {
                    *last_error.lock().unwrap() = Some(HANDSHAKE_FAILED_MSG.to_string());
                    set_state(&shared.state, ConnectionState::Error(HANDSHAKE_FAILED_MSG.into()));
                    break;
                }
            }
            Err(e) => {
                *last_error.lock().unwrap() = Some(e.clone());
                if is_terminal_error(&e) {
                    set_state(&shared.state, ConnectionState::Error(e));
                    break;
                }
            }
        }

        if shutdown.load(Ordering::Relaxed) { break; }
        set_state(&shared.state, ConnectionState::Reconnecting);

        let mut slept = 0u64;
        while slept < backoff_ms && !shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(BACKOFF_TICK_MS));
            slept += BACKOFF_TICK_MS;
        }
        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
    }

    let exit_tun = links.as_ref()
        .filter(|l| l.exit_state.is_some())
        .map(|l| l.tun.name().to_string());
    drop(links);
    if let Some(name) = exit_tun {
        route::emergency_cleanup(&name);
    }
    *shared.status_slot.lock().unwrap() = None;
    route::clear_active_session();
    if !matches!(*shared.state.lock().unwrap(), ConnectionState::Error(_)) {
        set_state(&shared.state, ConnectionState::Disconnected);
    }
}

fn run_attempt(
    config: &VpnConfig,
    shutdown: &Arc<AtomicBool>,
    shared: &SessionShared,
    links: &mut Option<SessionLinks>,
) -> Result<bool, String> {
    let private_key = crate::load_or_generate_key();
    let secret = StaticSecret::from(private_key);
    let public_key = PublicKey::from(&secret);
    let pub_key_b64 = crate::b64_encode(public_key.as_bytes());

    let mut client_name = config.name.clone();
    if client_name.is_empty() {
        client_name = crate::generate_client_name();
    }

    let advertise_routes: Vec<String> = if config.share_lan {
        crate::route::detect_local_subnets()
    } else {
        Vec::new()
    };

    let join_resp = if let Some(ref url) = config.join_url {
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

    if links.as_ref().is_some_and(|l| l.address != assigned_addr) {
        *links = None;
    }

    if links.is_none() {
        *links = Some(setup_links(config, &join_resp, ip, prefix, &assigned_addr, &server_endpoint)?);
    }

    let session = links.as_mut().ok_or("session links unavailable")?;
    session.sync_kill_switch(config, &server_endpoint);
    let tun_dev = &session.tun;

    let relay_name = config.relay_name.clone();

    let server_pub = PublicKey::from(server_pub_key);
    let keepalive = crate::jittered_keepalive();
    let tunn = Tunn::new(secret, server_pub, None, Some(keepalive), 0, None);
    let tunnel = Mutex::new(wg::WgState { tunn, server_pub_key: server_pub });

    *shared.status_slot.lock().unwrap() = Some(VpnStatus {
        tx: Arc::clone(&shared.tx),
        rx: Arc::clone(&shared.rx),
        connected_at: shared.connected_at,
        address: assigned_addr,
        address_v6: join_resp.address_v6.clone(),
        server: config.server.clone(),
        endpoint: server_endpoint.to_string(),
        tun_name: tun_dev.name().to_string(),
        internet_mode: config.internet,
        dns_protected: session.dns.is_some(),
        geo: Arc::clone(&shared.geo),
        geo_failed: Arc::clone(&shared.geo_failed),
    });

    let attempt_done = Arc::new(AtomicBool::new(false));
    let mesh_mgr = if join_resp.mesh.unwrap_or(false) {
        let mgr = Arc::new(mesh::MeshManager::new(private_key, mesh_port(config.listen_port)));
        if let Some(ref peers) = join_resp.mesh_peers {
            let parsed = api::parse_mesh_peers(peers);
            mgr.update_peers(&parsed, &pub_key_b64);
        }

        let refresh_mgr = Arc::clone(&mgr);
        let refresh_server = config.server.clone();
        let refresh_port = config.control_port;
        let refresh_token = config.token.clone();
        let refresh_pub_key = pub_key_b64.clone();
        let shutdown_ref = Arc::clone(shutdown);
        let done_ref = Arc::clone(&attempt_done);
        std::thread::spawn(move || {
            let interval = std::time::Duration::from_secs(30);
            loop {
                std::thread::sleep(interval);
                if shutdown_ref.load(Ordering::Relaxed) || done_ref.load(Ordering::Relaxed) { break; }
                let peers = api::get_mesh_peers(&refresh_server, refresh_port, &refresh_token);
                refresh_mgr.update_peers(&peers, &refresh_pub_key);
            }
        });
        Some(mgr)
    } else {
        None
    };

    let relay_addr = config.relay.clone().unwrap_or_default();
    if relay_addr.is_empty() {
        attempt_done.store(true, Ordering::Relaxed);
        *shared.status_slot.lock().unwrap() = None;
        return Err("no relay address configured".into());
    }

    set_state(&shared.state, ConnectionState::Handshaking);
    let rx_before = shared.rx.load(Ordering::Relaxed);

    let state_cb = Arc::clone(&shared.state);
    let sd_cb = Arc::clone(shutdown);
    let on_health = move |h: wg::LinkHealth| {
        if sd_cb.load(Ordering::Relaxed) { return; }
        let mut s = state_cb.lock().unwrap();
        match h {
            wg::LinkHealth::Connected => *s = ConnectionState::Connected,
            wg::LinkHealth::Degraded => *s = ConnectionState::Degraded,
        }
    };

    let on_health_ref: &dyn Fn(wg::LinkHealth) = &on_health;

    let target = relay_name.as_deref().unwrap_or(&config.server);
    let result = match wg::connect_relay(&relay_addr, target, &config.token) {
        Ok(mut stream) => {
            wg::run_data_plane_tls(
                tun_dev, &mut stream, &tunnel, &shared.tx, &shared.rx, shutdown,
                mesh_mgr.as_ref().map(|m| m.as_ref()), None, Some(on_health_ref),
            );
            Ok(shared.rx.load(Ordering::Relaxed) > rx_before)
        }
        Err(e) => Err(format!("connection failed: {}", e)),
    };

    attempt_done.store(true, Ordering::Relaxed);
    if !matches!(result, Ok(true)) {
        crate::cache::invalidate(&config.token);
    }
    *shared.status_slot.lock().unwrap() = None;
    drop(mesh_mgr);
    result
}

pub fn mesh_port(listen_port: u16) -> u16 {
    if listen_port == 0 { 0 } else { listen_port.saturating_add(1) }
}

fn setup_links(
    config: &VpnConfig,
    join_resp: &api::JoinResponse,
    ip: Ipv4Addr,
    prefix: u8,
    assigned_addr: &str,
    server_endpoint: &std::net::SocketAddr,
) -> Result<SessionLinks, String> {
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
                format!("{}:{}", config.server, config.control_port)
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

    let registered = config.internet || config.kill_switch.load(Ordering::Relaxed);
    if registered {
        route::register_active_tun(tun_dev.name());
    }

    let dns = if config.internet {
        let servers = resolve_dns_servers(join_resp.dns.as_ref(), &config.dns);
        if servers.is_empty() {
            None
        } else {
            match route::DnsState::apply(tun_dev.name(), &servers) {
                Ok(state) => Some(state),
                Err(e) => return Err(format!("dns setup failed: {}", e)),
            }
        }
    } else {
        None
    };

    Ok(SessionLinks {
        kill_switch: None,
        dns,
        exit_state,
        tun: tun_dev,
        address: assigned_addr.to_string(),
        registered,
    })
}
