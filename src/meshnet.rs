use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::meshapi::{self, MeshIdentity, MeshPeer, NetMap};
use crate::allowed::{self, Cidr};
use crate::{derp, disco, dns, exitnode, route, stun, tun};

pub const DEFAULT_MESH_PORT: u16 = 51821;
const BATCH: usize = 64;
const IDLE_SLEEP: Duration = Duration::from_micros(50);
const TIMER_TICK: Duration = Duration::from_millis(250);
const DISCO_PING_FAST: Duration = Duration::from_secs(2);
const DISCO_PING_SLOW: Duration = Duration::from_secs(15);
const PATH_FRESH: Duration = Duration::from_secs(20);
const STUN_INTERVAL: Duration = Duration::from_secs(60);
const STUN_PROBE_TTL: Duration = Duration::from_secs(10);
const NETMAP_BACKOFF: Duration = Duration::from_secs(5);
const PUBLISH_INTERVAL: Duration = Duration::from_secs(1);
const KEEPALIVE_SECS: u16 = 25;
const MAX_PACKET: usize = 65535;
const WG_OVERHEAD: usize = 148;
const DEFAULT_MTU: usize = 1280;
const IPV4_HEADER_MIN: usize = 20;
const IPV4_DST_OFFSET: usize = 16;
const PROBE_TARGET: &str = "8.8.8.8:53";
const ENDPOINT_QUEUE: usize = 4;

static PEER_INDEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

pub struct MeshConfig {
    pub user_token: String,
    pub network_id: Option<String>,
    pub project_id: Option<String>,
    pub device_name: String,
    pub mtu: usize,
    pub mesh_port: u16,
    pub exit_node: Option<String>,
    pub advertise_exit_node: bool,
    pub advertise_routes: Vec<String>,
    pub dns_upstream: String,
    pub manage_dns: bool,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            user_token: String::new(),
            network_id: None,
            project_id: None,
            device_name: String::new(),
            mtu: DEFAULT_MTU,
            mesh_port: DEFAULT_MESH_PORT,
            exit_node: None,
            advertise_exit_node: false,
            advertise_routes: Vec::new(),
            dns_upstream: String::new(),
            manage_dns: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeerPath {
    Offline,
    Relay,
    Direct,
}

#[derive(Clone)]
pub struct MeshPeerView {
    pub device_id: String,
    pub name: String,
    pub ip: String,
    pub path: PeerPath,
    pub rtt_ms: Option<u32>,
    pub exit_node: bool,
    pub online: bool,
    pub tx: u64,
    pub rx: u64,
}

#[derive(Clone)]
pub struct MeshStatus {
    pub tx: Arc<AtomicU64>,
    pub rx: Arc<AtomicU64>,
    pub device_id: String,
    pub name: String,
    pub address: String,
    pub network: String,
    pub routes: Vec<String>,
    pub advertising_exit: bool,
    pub dns_suffix: String,
    pub tun_name: String,
    pub exit_node: Option<String>,
    pub serving_exit: bool,
    pub relay_connected: Arc<AtomicBool>,
    pub peers: Arc<Mutex<Vec<MeshPeerView>>>,
    pub connection_dropped: Arc<AtomicBool>,
    pub stopped: Arc<AtomicBool>,
    pub connected_at: Instant,
}

struct Candidate {
    addr: SocketAddr,
    lan: bool,
    last_ping: Option<Instant>,
    last_pong: Option<Instant>,
    rtt: Option<Duration>,
    tx_id: [u8; 8],
}

struct Peer {
    device_id: String,
    name: String,
    key: [u8; 32],
    key_b64: String,
    ip: Ipv4Addr,
    allowed: Vec<Cidr>,
    exit_node: bool,
    online: bool,
    tunn: Tunn,
    candidates: Vec<Candidate>,
    best: Option<SocketAddr>,
    last_counter: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

pub fn connect(config: MeshConfig, shutdown: Arc<AtomicBool>) -> Result<MeshStatus, String> {
    let private_key = crate::load_or_generate_key();
    let secret = StaticSecret::from(private_key);
    let public_key_b64 = crate::b64_encode(PublicKey::from(&secret).as_bytes());

    let identity = resolve_identity(&config, &public_key_b64)?;
    let netmap = meshapi::netmap(&identity.token, 0)?;
    let network = if netmap.network.cidr.is_empty() {
        identity.network.clone()
    } else {
        netmap.network.clone()
    };

    let (self_ip, prefix) = parse_cidr(&netmap.device.mesh_ip, &network.cidr)?;
    let (net_ip, net_prefix) = parse_network(&network.cidr)?;

    let tun_dev = tun::TunDevice::try_create(config.mtu)?;
    tun_dev.set_address(self_ip, prefix);
    tun_dev.set_up();
    let tun_name = tun_dev.name().to_string();

    let _ = route::add_route(net_ip, net_prefix, &tun_name);

    let udp = bind_mesh_socket(config.mesh_port)?;
    let local_port = udp.local_addr().map(|a| a.port()).unwrap_or(config.mesh_port);

    let relay_host = netmap
        .relays
        .first()
        .or_else(|| identity.relays.first())
        .cloned()
        .ok_or_else(|| "mesh: control plane returned no relay".to_string())?;

    let derp_client = derp::DerpClient::start(
        relay_host.clone(),
        identity.token.clone(),
        public_key_b64.clone(),
        Arc::clone(&shutdown),
    );

    let exit_peer = config
        .exit_node
        .as_ref()
        .and_then(|id| netmap.peers.iter().find(|p| &p.device_id == id && p.exit_node))
        .cloned();

    let exit_state = match exit_peer.as_ref() {
        Some(peer) => Some(setup_exit_routes(peer, &relay_host, &tun_name)?),
        None => None,
    };

    let serving = config.advertise_exit_node && exitnode::ExitNodeState::is_supported();
    let exit_node_state = if serving {
        exitnode::ExitNodeState::activate(&tun_name, &network.cidr, None).ok()
    } else {
        None
    };

    let peer_names: Arc<RwLock<HashMap<String, Ipv4Addr>>> =
        Arc::new(RwLock::new(name_map(&netmap.peers)));
    let dns_guard = if config.manage_dns {
        start_dns(&config, &network, self_ip, &peer_names, &shutdown)
    } else {
        None
    };

    let status = MeshStatus {
        tx: Arc::new(AtomicU64::new(0)),
        rx: Arc::new(AtomicU64::new(0)),
        device_id: netmap.device.device_id.clone(),
        name: netmap.device.name.clone(),
        address: self_ip.to_string(),
        network: network.cidr.clone(),
        routes: netmap.device.routes.clone(),
        advertising_exit: netmap.device.exit_node,
        dns_suffix: network.dns_suffix.clone(),
        tun_name: tun_name.clone(),
        exit_node: exit_peer.as_ref().map(|p| p.device_id.clone()),
        serving_exit: exit_node_state.is_some(),
        relay_connected: Arc::new(AtomicBool::new(false)),
        peers: Arc::new(Mutex::new(Vec::new())),
        connection_dropped: Arc::new(AtomicBool::new(false)),
        stopped: Arc::new(AtomicBool::new(false)),
        connected_at: Instant::now(),
    };

    let pending: Arc<Mutex<Option<NetMap>>> = Arc::new(Mutex::new(Some(netmap)));
    spawn_netmap_poller(
        identity.token.clone(),
        Arc::clone(&pending),
        Arc::clone(&shutdown),
    );

    let session = SessionHandles {
        status: status.clone(),
        peer_names,
        pending,
        selected_exit: config.exit_node.clone(),
        self_key: PublicKey::from(&secret).to_bytes(),
        disco_secret: decode_secret(&network.disco_secret),
        endpoints: spawn_endpoint_reporter(identity.token.clone(), Arc::clone(&shutdown)),
        local_port,
    };

    let had_exit_route = exit_state.is_some();
    let stopped = Arc::clone(&status.stopped);
    std::thread::spawn(move || {
        {
            let _dns_guard = dns_guard;
            let _exit_node_state = exit_node_state;
            run_session(
                session,
                private_key,
                tun_dev,
                udp,
                derp_client,
                exit_state,
                shutdown.clone(),
            );
            if had_exit_route {
                route::emergency_cleanup(&tun_name);
            } else {
                route::cleanup_tun_routes(&tun_name);
            }
        }
        stopped.store(true, Ordering::Relaxed);
    });

    Ok(status)
}

struct SessionHandles {
    status: MeshStatus,
    peer_names: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    pending: Arc<Mutex<Option<NetMap>>>,
    selected_exit: Option<String>,
    self_key: [u8; 32],
    disco_secret: Vec<u8>,
    endpoints: SyncSender<Vec<String>>,
    local_port: u16,
}

fn run_session(
    handles: SessionHandles,
    private_key: [u8; 32],
    tun_dev: tun::TunDevice,
    udp: UdpSocket,
    derp_client: derp::DerpClient,
    mut exit_state: Option<route::ExitRouteState>,
    shutdown: Arc<AtomicBool>,
) {
    let mut peers: Vec<Peer> = Vec::new();
    let mut by_addr: HashMap<SocketAddr, usize> = HashMap::new();
    let mut by_key: HashMap<[u8; 32], usize> = HashMap::new();
    let mut stun_probes: Vec<(stun::Probe, Instant)> = Vec::new();
    let mut installed_routes: HashSet<String> = HashSet::new();
    let mut public_endpoint: Option<SocketAddr> = None;
    let mut counter = initial_counter();

    let mut read_buf = vec![0u8; MAX_PACKET];
    let mut scratch = vec![0u8; MAX_PACKET + WG_OVERHEAD];
    let mut last_timer = Instant::now();
    let mut last_stun = Instant::now() - STUN_INTERVAL;
    let mut last_publish = Instant::now();

    report_local_endpoints(&handles);

    while !shutdown.load(Ordering::Relaxed) {
        let mut busy = false;

        if let Some(map) = handles.pending.lock().ok().and_then(|mut p| p.take()) {
            apply_netmap(
                &map,
                &mut peers,
                &private_key,
                &handles,
                &tun_dev,
                &mut exit_state,
                &mut installed_routes,
            );
            rebuild_index(&peers, &mut by_addr, &mut by_key);
            if let Ok(mut names) = handles.peer_names.write() {
                *names = name_map(&map.peers);
            }
            busy = true;
        }

        for _ in 0..BATCH {
            match tun_dev.read_packet(&mut read_buf) {
                Ok(n) if n >= IPV4_HEADER_MIN => {
                    busy = true;
                    let dst = u32::from_be_bytes([
                        read_buf[IPV4_DST_OFFSET],
                        read_buf[IPV4_DST_OFFSET + 1],
                        read_buf[IPV4_DST_OFFSET + 2],
                        read_buf[IPV4_DST_OFFSET + 3],
                    ]);
                    if let Some(idx) = route_lookup(&peers, dst) {
                        let sent = encapsulate_and_send(
                            &mut peers[idx],
                            &read_buf[..n],
                            &mut scratch,
                            &udp,
                            &derp_client,
                        );
                        if sent {
                            handles.status.tx.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        loop {
            match udp.recv_from(&mut read_buf) {
                Ok((n, from)) => {
                    busy = true;
                    let data = &read_buf[..n];
                    if disco::is_disco(data) {
                        handle_disco(
                            data,
                            from,
                            &handles,
                            &mut peers,
                            &mut by_addr,
                            &udp,
                            &mut counter,
                            &mut public_endpoint,
                        );
                    } else if stun::is_binding_response(data) {
                        handle_stun(data, &mut stun_probes, &mut public_endpoint, &handles);
                    } else if let Some(idx) = by_addr.get(&from).copied() {
                        if let Some(received) = decapsulate_into_tun(
                            &mut peers[idx],
                            data,
                            &mut scratch,
                            &tun_dev,
                            &udp,
                            &derp_client,
                            Some(from),
                        ) {
                            handles.status.rx.fetch_add(received, Ordering::Relaxed);
                        }
                    } else {
                        for idx in 0..peers.len() {
                            if let Some(received) = decapsulate_into_tun(
                                &mut peers[idx],
                                data,
                                &mut scratch,
                                &tun_dev,
                                &udp,
                                &derp_client,
                                Some(from),
                            ) {
                                by_addr.insert(from, idx);
                                handles.status.rx.fetch_add(received, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        while let Some((src, data)) = derp_client.try_recv() {
            busy = true;
            if let Some(&idx) = by_key.get(&src) {
                if let Some(received) = decapsulate_into_tun(
                    &mut peers[idx],
                    &data,
                    &mut scratch,
                    &tun_dev,
                    &udp,
                    &derp_client,
                    None,
                ) {
                    handles.status.rx.fetch_add(received, Ordering::Relaxed);
                }
            }
        }

        let now = Instant::now();
        if now.duration_since(last_timer) >= TIMER_TICK {
            last_timer = now;
            for peer in peers.iter_mut() {
                match peer.tunn.update_timers(&mut scratch) {
                    TunnResult::WriteToNetwork(data) => {
                        transmit(peer, data, &udp, &derp_client);
                    }
                    _ => {}
                }
                disco_tick(peer, &udp, &handles, &mut counter, now);
                select_path(peer, now);
            }
            handles
                .status
                .relay_connected
                .store(derp_client.is_connected(), Ordering::Relaxed);
            if let Some(state) = exit_state.as_mut() {
                preserve_exit_paths(&peers, &handles.selected_exit, state);
            }
        }

        if now.duration_since(last_stun) >= STUN_INTERVAL {
            last_stun = now;
            stun_probes.retain(|(_, sent)| now.duration_since(*sent) < STUN_PROBE_TTL);
            for server in stun::servers() {
                if let Some(addr) = stun::resolve(&server) {
                    if let Some(probe) = stun::Probe::send(&udp, addr) {
                        stun_probes.push((probe, now));
                    }
                }
            }
        }

        if now.duration_since(last_publish) >= PUBLISH_INTERVAL {
            last_publish = now;
            publish_peers(&peers, &handles);
        }

        if !busy {
            std::thread::sleep(IDLE_SLEEP);
        }
    }

    handles
        .status
        .connection_dropped
        .store(true, Ordering::Relaxed);
}

fn resolve_identity(config: &MeshConfig, public_key_b64: &str) -> Result<MeshIdentity, String> {
    if let Some(existing) = meshapi::load_identity() {
        let network_matches = config
            .network_id
            .as_ref()
            .map_or(true, |id| id == &existing.network.id);
        if existing.public_key == public_key_b64 && !existing.token.is_empty() && network_matches {
            return Ok(existing);
        }
    }
    let user_token = if config.user_token.is_empty() {
        crate::api::load_account_token()
            .ok_or_else(|| "Sign in to join your mesh network.".to_string())?
    } else {
        config.user_token.clone()
    };
    let request = meshapi::EnrollRequest {
        network_id: config.network_id.clone(),
        project_id: config.project_id.clone(),
        name: config.device_name.clone(),
        public_key: public_key_b64.to_string(),
        os: meshapi::os_name(),
        os_version: meshapi::os_version(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        advertise_exit_node: config.advertise_exit_node,
        advertise_routes: config.advertise_routes.clone(),
    };
    let identity = meshapi::enroll(&user_token, &request)?;
    meshapi::save_identity(&identity);
    Ok(identity)
}

fn spawn_netmap_poller(
    token: String,
    pending: Arc<Mutex<Option<NetMap>>>,
    shutdown: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let mut version = 0u64;
        while !shutdown.load(Ordering::Relaxed) {
            match meshapi::netmap(&token, version) {
                Ok(map) => {
                    version = map.version;
                    if let Ok(mut slot) = pending.lock() {
                        *slot = Some(map);
                    }
                }
                Err(_) => std::thread::sleep(NETMAP_BACKOFF),
            }
        }
    });
}

fn apply_netmap(
    map: &NetMap,
    peers: &mut Vec<Peer>,
    private_key: &[u8; 32],
    handles: &SessionHandles,
    tun_dev: &tun::TunDevice,
    exit_state: &mut Option<route::ExitRouteState>,
    installed_routes: &mut HashSet<String>,
) {
    peers.retain(|p| map.peers.iter().any(|mp| mp.public_key == p.key_b64));
    let exit_active = exit_state.is_some();

    for entry in &map.peers {
        let key = match decode_key(&entry.public_key) {
            Some(k) => k,
            None => continue,
        };
        let ip = match entry.mesh_ip.parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let is_exit = exit_active
            && entry.exit_node
            && handles
                .selected_exit
                .as_ref()
                .map_or(false, |id| id == &entry.device_id);
        let allowed = build_allowed(entry, ip, is_exit);

        match peers.iter_mut().find(|p| p.key_b64 == entry.public_key) {
            Some(peer) => {
                peer.name = entry.name.clone();
                peer.device_id = entry.device_id.clone();
                peer.ip = ip;
                peer.allowed = allowed;
                peer.exit_node = entry.exit_node;
                peer.online = entry.online;
                merge_candidates(peer, &entry.endpoints);
            }
            None => {
                let tunn = Tunn::new(
                    StaticSecret::from(*private_key),
                    PublicKey::from(key),
                    None,
                    Some(KEEPALIVE_SECS),
                    PEER_INDEX.fetch_add(1, Ordering::Relaxed),
                    None,
                );
                let mut peer = Peer {
                    device_id: entry.device_id.clone(),
                    name: entry.name.clone(),
                    key,
                    key_b64: entry.public_key.clone(),
                    ip,
                    allowed,
                    exit_node: entry.exit_node,
                    online: entry.online,
                    tunn,
                    candidates: Vec::new(),
                    best: None,
                    last_counter: 0,
                    tx_bytes: 0,
                    rx_bytes: 0,
                };
                merge_candidates(&mut peer, &entry.endpoints);
                peers.push(peer);
            }
        }
    }

    install_peer_routes(&map.peers, tun_dev.name(), installed_routes);
    if let Some(state) = exit_state.as_mut() {
        preserve_exit_paths(peers, &handles.selected_exit, state);
    }
}

fn build_allowed(entry: &MeshPeer, ip: Ipv4Addr, is_selected_exit: bool) -> Vec<Cidr> {
    let mut table = vec![allowed::host(ip)];
    for cidr in &entry.routes {
        if let Some(parsed) = allowed::parse(cidr).filter(|p| p.2 > 0) {
            table.push(parsed);
        }
    }
    if is_selected_exit {
        table.push(allowed::DEFAULT_ROUTE);
    }
    table
}

fn merge_candidates(peer: &mut Peer, endpoints: &[String]) {
    for raw in endpoints {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            add_candidate(peer, addr);
        }
    }
}

fn add_candidate(peer: &mut Peer, addr: SocketAddr) {
    if peer.candidates.iter().any(|c| c.addr == addr) {
        return;
    }
    peer.candidates.push(Candidate {
        addr,
        lan: is_private(addr.ip()),
        last_ping: None,
        last_pong: None,
        rtt: None,
        tx_id: [0u8; 8],
    });
}

fn route_lookup(peers: &[Peer], dst: u32) -> Option<usize> {
    peers
        .iter()
        .enumerate()
        .filter_map(|(idx, peer)| allowed::best_prefix(&peer.allowed, dst).map(|p| (idx, p)))
        .max_by_key(|&(_, prefix)| prefix)
        .map(|(idx, _)| idx)
}

fn encapsulate_and_send(
    peer: &mut Peer,
    packet: &[u8],
    scratch: &mut [u8],
    udp: &UdpSocket,
    relay: &derp::DerpClient,
) -> bool {
    match peer.tunn.encapsulate(packet, scratch) {
        TunnResult::WriteToNetwork(data) => {
            let len = data.len() as u64;
            let sent = send_raw(peer.best, &peer.key, data, udp, relay);
            if sent {
                peer.tx_bytes += len;
            }
            sent
        }
        _ => false,
    }
}

fn transmit(peer: &mut Peer, data: &[u8], udp: &UdpSocket, relay: &derp::DerpClient) {
    let len = data.len() as u64;
    if send_raw(peer.best, &peer.key, data, udp, relay) {
        peer.tx_bytes += len;
    }
}

fn send_raw(
    best: Option<SocketAddr>,
    key: &[u8; 32],
    data: &[u8],
    udp: &UdpSocket,
    relay: &derp::DerpClient,
) -> bool {
    if let Some(addr) = best {
        if udp.send_to(data, addr).is_ok() {
            return true;
        }
    }
    relay.send(key, data)
}

fn decapsulate_into_tun(
    peer: &mut Peer,
    data: &[u8],
    scratch: &mut [u8],
    tun_dev: &tun::TunDevice,
    udp: &UdpSocket,
    relay: &derp::DerpClient,
    from: Option<SocketAddr>,
) -> Option<u64> {
    let mut received = 0u64;
    match peer.tunn.decapsulate(None, data, scratch) {
        TunnResult::Err(_) => return None,
        TunnResult::WriteToTunnelV4(packet, _) => {
            received = packet.len() as u64;
            let _ = tun_dev.write_packet(packet);
        }
        TunnResult::WriteToTunnelV6(packet, _) => {
            received = packet.len() as u64;
            let _ = tun_dev.write_packet(packet);
        }
        TunnResult::WriteToNetwork(reply) => {
            let len = reply.len() as u64;
            if send_raw(from.or(peer.best), &peer.key, reply, udp, relay) {
                peer.tx_bytes += len;
            }
            loop {
                match peer.tunn.decapsulate(None, &[], scratch) {
                    TunnResult::WriteToNetwork(more) => {
                        let len = more.len() as u64;
                        if send_raw(from.or(peer.best), &peer.key, more, udp, relay) {
                            peer.tx_bytes += len;
                        }
                    }
                    TunnResult::WriteToTunnelV4(packet, _) => {
                        received += packet.len() as u64;
                        let _ = tun_dev.write_packet(packet);
                        break;
                    }
                    _ => break,
                }
            }
        }
        _ => {}
    }
    if received > 0 {
        peer.rx_bytes += received;
    }
    Some(received)
}

fn handle_disco(
    data: &[u8],
    from: SocketAddr,
    handles: &SessionHandles,
    peers: &mut [Peer],
    by_addr: &mut HashMap<SocketAddr, usize>,
    udp: &UdpSocket,
    counter: &mut u64,
    public_endpoint: &mut Option<SocketAddr>,
) {
    let message = match disco::decode(&handles.disco_secret, data) {
        Some(m) => m,
        None => return,
    };
    let idx = match peers.iter().position(|p| p.key == message.sender) {
        Some(i) => i,
        None => return,
    };
    if message.counter <= peers[idx].last_counter {
        return;
    }
    peers[idx].last_counter = message.counter;
    by_addr.insert(from, idx);

    match message.kind {
        disco::PING => {
            add_candidate(&mut peers[idx], from);
            *counter += 1;
            let reply = disco::encode(
                &handles.disco_secret,
                disco::PONG,
                &handles.self_key,
                *counter,
                &message.tx_id,
                Some(from),
            );
            let _ = udp.send_to(&reply, from);
        }
        disco::PONG => {
            let now = Instant::now();
            if let Some(cand) = peers[idx].candidates.iter_mut().find(|c| c.tx_id == message.tx_id) {
                cand.last_pong = Some(now);
                cand.rtt = cand.last_ping.map(|sent| now.duration_since(sent));
            }
            if let Some(observed) = message.observed {
                publish_endpoint(observed, public_endpoint, handles);
            }
        }
        _ => {}
    }
}

fn handle_stun(
    data: &[u8],
    probes: &mut Vec<(stun::Probe, Instant)>,
    public_endpoint: &mut Option<SocketAddr>,
    handles: &SessionHandles,
) {
    let mut found = None;
    for (probe, _) in probes.iter() {
        if let Some(addr) = probe.parse(data) {
            found = Some(addr);
            break;
        }
    }
    let addr = match found {
        Some(a) => a,
        None => return,
    };
    probes.clear();
    publish_endpoint(addr, public_endpoint, handles);
}

fn initial_counter() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

fn spawn_endpoint_reporter(token: String, shutdown: Arc<AtomicBool>) -> SyncSender<Vec<String>> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<String>>(ENDPOINT_QUEUE);
    std::thread::spawn(move || {
        while let Ok(mut latest) = rx.recv() {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            while let Ok(newer) = rx.try_recv() {
                latest = newer;
            }
            let _ = meshapi::report_endpoints(&token, &latest);
        }
    });
    tx
}

fn report_local_endpoints(handles: &SessionHandles) {
    let endpoints = local_endpoints(handles.local_port);
    if !endpoints.is_empty() {
        let _ = handles.endpoints.try_send(endpoints);
    }
}

fn publish_endpoint(
    addr: SocketAddr,
    public_endpoint: &mut Option<SocketAddr>,
    handles: &SessionHandles,
) {
    if public_endpoint.as_ref() == Some(&addr) {
        return;
    }
    *public_endpoint = Some(addr);

    let mut endpoints: Vec<String> = vec![addr.to_string()];
    endpoints.extend(local_endpoints(handles.local_port));
    endpoints.dedup();
    let _ = handles.endpoints.try_send(endpoints);
}

fn disco_tick(
    peer: &mut Peer,
    udp: &UdpSocket,
    handles: &SessionHandles,
    counter: &mut u64,
    now: Instant,
) {
    let interval = if peer.best.is_some() {
        DISCO_PING_SLOW
    } else {
        DISCO_PING_FAST
    };
    for cand in peer.candidates.iter_mut() {
        if cand.last_ping.map_or(false, |t| now.duration_since(t) < interval) {
            continue;
        }
        cand.last_ping = Some(now);
        crate::rng::fill(&mut cand.tx_id);
        *counter += 1;
        let ping = disco::encode(
            &handles.disco_secret,
            disco::PING,
            &handles.self_key,
            *counter,
            &cand.tx_id,
            None,
        );
        let _ = udp.send_to(&ping, cand.addr);
    }
}

fn select_path(peer: &mut Peer, now: Instant) {
    let mut best: Option<(SocketAddr, Duration, bool)> = None;
    for cand in &peer.candidates {
        let (pong, rtt) = match (cand.last_pong, cand.rtt) {
            (Some(p), Some(r)) => (p, r),
            _ => continue,
        };
        if now.duration_since(pong) > PATH_FRESH {
            continue;
        }
        let better = match best {
            None => true,
            Some((_, best_rtt, best_lan)) => {
                (cand.lan && !best_lan) || (cand.lan == best_lan && rtt < best_rtt)
            }
        };
        if better {
            best = Some((cand.addr, rtt, cand.lan));
        }
    }
    peer.best = best.map(|(addr, _, _)| addr);
}

fn rebuild_index(
    peers: &[Peer],
    by_addr: &mut HashMap<SocketAddr, usize>,
    by_key: &mut HashMap<[u8; 32], usize>,
) {
    by_addr.clear();
    by_key.clear();
    for (idx, peer) in peers.iter().enumerate() {
        by_key.insert(peer.key, idx);
        for cand in &peer.candidates {
            by_addr.insert(cand.addr, idx);
        }
    }
}

fn publish_peers(peers: &[Peer], handles: &SessionHandles) {
    let views: Vec<MeshPeerView> = peers
        .iter()
        .map(|p| MeshPeerView {
            device_id: p.device_id.clone(),
            name: p.name.clone(),
            ip: p.ip.to_string(),
            path: if p.best.is_some() {
                PeerPath::Direct
            } else if p.online {
                PeerPath::Relay
            } else {
                PeerPath::Offline
            },
            rtt_ms: p
                .candidates
                .iter()
                .filter(|c| Some(c.addr) == p.best)
                .find_map(|c| c.rtt)
                .map(|d| d.as_millis() as u32),
            exit_node: p.exit_node,
            online: p.online,
            tx: p.tx_bytes,
            rx: p.rx_bytes,
        })
        .collect();
    if let Ok(mut slot) = handles.status.peers.lock() {
        *slot = views;
    }
}

fn preserve_exit_paths(
    peers: &[Peer],
    selected: &Option<String>,
    state: &mut route::ExitRouteState,
) {
    let id = match selected {
        Some(id) => id,
        None => return,
    };
    if let Some(peer) = peers.iter().find(|p| &p.device_id == id) {
        for cand in &peer.candidates {
            state.preserve(&cand.addr.ip().to_string());
        }
    }
}

fn setup_exit_routes(
    peer: &MeshPeer,
    relay_host: &str,
    tun_name: &str,
) -> Result<route::ExitRouteState, String> {
    let mut preserve: Vec<String> = Vec::new();
    for endpoint in &peer.endpoints {
        if let Ok(addr) = endpoint.parse::<SocketAddr>() {
            preserve.push(addr.ip().to_string());
        }
    }
    preserve.extend(resolve_host_ips(relay_host));
    preserve.extend(resolve_host_ips(&crate::api::api_host()));
    let refs: Vec<&str> = preserve.iter().map(|s| s.as_str()).collect();
    route::ExitRouteState::setup_dual(&refs, tun_name, false)
}

fn resolve_host_ips(host: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let target = if host.contains(':') {
        host.to_string()
    } else {
        format!("{}:443", host)
    };
    target
        .to_socket_addrs()
        .map(|addrs| {
            addrs
                .filter(|a| !a.ip().is_loopback() && !a.ip().is_unspecified())
                .map(|a| a.ip().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn install_peer_routes(peers: &[MeshPeer], tun_name: &str, installed: &mut HashSet<String>) {
    for peer in peers {
        for cidr in &peer.routes {
            if installed.contains(cidr) {
                continue;
            }
            if let Some((net, prefix)) = allowed::network(cidr).filter(|p| p.1 > 0) {
                if route::add_route(net, prefix, tun_name).is_ok() {
                    installed.insert(cidr.clone());
                }
            }
        }
    }
}

fn start_dns(
    config: &MeshConfig,
    network: &meshapi::MeshNetwork,
    self_ip: Ipv4Addr,
    peer_names: &Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    shutdown: &Arc<AtomicBool>,
) -> Option<route::DnsGuard> {
    let upstream = if config.dns_upstream.is_empty() {
        std::env::var("NEXGUARD_DNS_UPSTREAM").unwrap_or_else(|_| "1.1.1.1".to_string())
    } else {
        config.dns_upstream.clone()
    };
    let resolver = dns::DnsResolver::try_start(
        &self_ip.to_string(),
        &upstream,
        &network.dns_suffix,
        Arc::clone(peer_names),
    )?;
    let advertise = resolver.resolver_address()?.ip().to_string();
    let dns_shutdown = Arc::clone(shutdown);
    std::thread::spawn(move || {
        resolver.run_with_shutdown(&dns_shutdown);
    });
    route::set_system_dns(&advertise)
}

fn name_map(peers: &[MeshPeer]) -> HashMap<String, Ipv4Addr> {
    peers
        .iter()
        .filter(|p| !p.name.is_empty())
        .filter_map(|p| p.mesh_ip.parse::<Ipv4Addr>().ok().map(|ip| (p.name.to_lowercase(), ip)))
        .collect()
}

fn bind_mesh_socket(port: u16) -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind(("0.0.0.0", port))
        .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
        .map_err(|e| format!("mesh socket: {}", e))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("mesh socket nonblocking: {}", e))?;
    Ok(socket)
}

fn local_endpoints(port: u16) -> Vec<String> {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect(PROBE_TARGET)?;
            s.local_addr()
        })
        .ok()
        .filter(|addr| !addr.ip().is_loopback() && !addr.ip().is_unspecified())
        .map(|addr| vec![SocketAddr::new(addr.ip(), port).to_string()])
        .unwrap_or_default()
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn decode_key(value: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn decode_secret(value: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .unwrap_or_else(|_| value.as_bytes().to_vec())
}

fn parse_network(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    allowed::network(cidr).ok_or_else(|| format!("mesh: invalid network {}", cidr))
}

fn parse_cidr(address: &str, network: &str) -> Result<(Ipv4Addr, u8), String> {
    let ip: Ipv4Addr = address
        .split('/')
        .next()
        .unwrap_or(address)
        .trim()
        .parse()
        .map_err(|_| format!("mesh: invalid address {}", address))?;
    let prefix = allowed::network(network)
        .map(|(_, p)| p)
        .ok_or_else(|| format!("mesh: invalid network {}", network))?;
    Ok((ip, prefix))
}
