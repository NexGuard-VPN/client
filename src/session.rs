use crate::dns;
use crate::meshnet::{self, MeshStatus};
use crate::meshtypes::{MeshConfig, MeshPeerView, PeerPath};
use crate::profiles;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const API_HOST_ENV: &str = "NEXGUARD_API_HOST";
const STOP_GRACE: Duration = Duration::from_millis(2000);
const STOP_POLL: Duration = Duration::from_millis(20);

#[derive(Deserialize, Default)]
pub struct HostConfig {
    #[serde(default)]
    api_base: String,
    #[serde(default)]
    account_token: String,
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    storage_dir: String,
    #[serde(default)]
    exit_node: String,
    /// The resolver the host wants names outside the mesh sent to. A phone
    /// knows which one it was using before the tunnel took the queries over;
    /// the core cannot see past its own interface to find out.
    #[serde(default)]
    dns_upstream: String,
    #[serde(default)]
    mtu: usize,
}

struct Session {
    status: MeshStatus,
    shutdown: Arc<AtomicBool>,
}

fn sessions() -> &'static Mutex<Option<Session>> {
    static SESSION: OnceLock<Mutex<Option<Session>>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(None))
}

fn last_error() -> &'static Mutex<String> {
    static ERROR: OnceLock<Mutex<String>> = OnceLock::new();
    ERROR.get_or_init(|| Mutex::new(String::new()))
}

fn remember_error(reason: &str) {
    if let Ok(mut slot) = last_error().lock() {
        *slot = reason.to_owned();
    }
}

fn taken_error() -> String {
    last_error().lock().map(|e| e.clone()).unwrap_or_default()
}

/// The host names an API base like `https://api.nexguard.sh`; the client speaks
/// to a host and always over TLS.
pub fn api_host(base: &str) -> Option<String> {
    let trimmed = base.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = without_scheme.split('/').next().unwrap_or("").trim();
    (!host.is_empty()).then(|| host.to_owned())
}

fn optional(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn apply_environment(host: &HostConfig) {
    if let Some(dir) = optional(&host.storage_dir) {
        profiles::set_config_dir(PathBuf::from(dir));
    }
    if let Some(name) = api_host(&host.api_base) {
        std::env::set_var(API_HOST_ENV, name);
    }
}

fn mesh_config(host: &HostConfig, tun_fd: Option<i32>) -> MeshConfig {
    let mut config = MeshConfig {
        user_token: host.account_token.trim().to_owned(),
        project_id: optional(&host.project_id),
        exit_node: optional(&host.exit_node),
        // A phone hands its tunnel to the system and never sets up the
        // forwarding an exit node needs, so it can use one but never be one.
        advertise_exit_node: false,
        manage_dns: false,
        dns_upstream: optional(&host.dns_upstream).unwrap_or_default(),
        hosted_tun: tun_fd,
        ..MeshConfig::default()
    };
    config.device_name = optional(&host.device_name).unwrap_or_else(crate::generate_client_name);
    if host.mtu > 0 {
        config.mtu = host.mtu;
    }
    config
}

fn failure(reason: &str) -> String {
    remember_error(reason);
    json!({ "ok": false, "error": reason }).to_string()
}

fn prefix_of(cidr: &str) -> u8 {
    cidr.split('/')
        .nth(1)
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or(32)
}

fn parse(config_json: &str) -> Result<HostConfig, String> {
    let host: HostConfig =
        serde_json::from_str(config_json).map_err(|e| format!("configuration: {}", e))?;
    if host.account_token.trim().is_empty() {
        return Err("the account is not signed in".to_owned());
    }
    Ok(host)
}

/// Enrols the device, or reuses the identity it already holds, and answers with
/// everything the host needs to configure its own tunnel before handing the
/// descriptor over. Performs network calls: never call it on a UI thread.
pub fn prepare(config_json: &str) -> String {
    remember_error("");
    let host = match parse(config_json) {
        Ok(host) => host,
        Err(reason) => return failure(&reason),
    };
    apply_environment(&host);
    let config = mesh_config(&host, None);
    let identity = match meshnet::enroll(&config) {
        Ok(identity) => identity,
        Err(reason) => return failure(&reason),
    };
    json!({
        "ok": true,
        "address": identity.mesh_ip,
        "prefix": prefix_of(&identity.network.cidr),
        "network": identity.network.cidr,
        "dns_suffix": dns::zone_name(&identity.network.dns_suffix),
        "dns_address": dns::RESOLVER.to_string(),
        "mtu": config.mtu,
        "device_id": identity.device_id,
        "name": config.device_name,
        "project_id": identity.network.project_id,
    })
    .to_string()
}

/// Runs the mesh on a descriptor the host already created and routed. Performs
/// network calls: never call it on a UI thread.
pub fn start(tun_fd: i32, config_json: &str) -> i32 {
    stop();
    let host = match parse(config_json) {
        Ok(host) => host,
        Err(reason) => {
            remember_error(&reason);
            return -1;
        }
    };
    apply_environment(&host);
    let shutdown = Arc::new(AtomicBool::new(false));
    match meshnet::connect(mesh_config(&host, Some(tun_fd)), Arc::clone(&shutdown)) {
        Ok(status) => {
            remember_error("");
            if let Ok(mut slot) = sessions().lock() {
                *slot = Some(Session { status, shutdown });
            }
            0
        }
        Err(reason) => {
            remember_error(&reason);
            -1
        }
    }
}

fn path_name(path: &PeerPath) -> &'static str {
    match path {
        PeerPath::Direct => "direct",
        PeerPath::Relay => "relay",
        PeerPath::Offline => "offline",
    }
}

fn peer_json(peer: &MeshPeerView) -> Value {
    json!({
        "device_id": peer.device_id,
        "name": peer.name,
        "ip": peer.ip,
        "online": peer.online,
        "path": path_name(&peer.path),
        "rtt_ms": peer.rtt_ms,
        "exit_node": peer.exit_node,
        "tx": peer.tx,
        "rx": peer.rx,
    })
}

fn idle_status() -> String {
    let error = taken_error();
    json!({
        "state": if error.is_empty() { "disconnected" } else { "error" },
        "error": if error.is_empty() { Value::Null } else { Value::String(error) },
        "peers": [],
    })
    .to_string()
}

pub fn status() -> String {
    let guard = match sessions().lock() {
        Ok(guard) => guard,
        Err(_) => return idle_status(),
    };
    let session = match guard.as_ref() {
        Some(session) => session,
        None => return idle_status(),
    };
    let status = &session.status;
    if status.stopped.load(Ordering::Relaxed) {
        return idle_status();
    }
    let peers: Vec<Value> = status
        .peers
        .lock()
        .map(|peers| peers.iter().map(peer_json).collect())
        .unwrap_or_default();
    json!({
        "state": if status.connection_dropped.load(Ordering::Relaxed) { "connecting" } else { "connected" },
        "error": Value::Null,
        "address": status.address,
        "network": status.network,
        "dns_suffix": status.dns_suffix,
        "device_id": status.device_id,
        "name": status.name,
        "tx": status.tx.load(Ordering::Relaxed),
        "rx": status.rx.load(Ordering::Relaxed),
        "uptime_secs": status.connected_at.elapsed().as_secs(),
        "relay_connected": status.relay_connected.load(Ordering::Relaxed),
        "exit_node": status.exit_node,
        "serving_exit": status.serving_exit,
        "peers": peers,
    })
    .to_string()
}

pub fn stop() {
    remember_error("");
    let session = match sessions().lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    };
    let session = match session {
        Some(session) => session,
        None => return,
    };
    session.shutdown.store(true, Ordering::Relaxed);
    let deadline = std::time::Instant::now() + STOP_GRACE;
    while !session.status.stopped.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
        std::thread::sleep(STOP_POLL);
    }
}
