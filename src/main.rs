mod api;
pub mod fingerprint;
pub mod mesh;
mod profiles;
mod route;
pub mod tun;
mod ui;
mod vpn;
mod wg;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
const OBFS_PORT: u16 = 443;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let cli_mode = args.iter().any(|a| a == "--cli" || a == "--no-gui");
    let init_server = arg_value(&args, "--server").or_else(|| arg_value(&args, "-s"));
    let init_token = arg_value(&args, "--token").or_else(|| arg_value(&args, "-t"));
    let init_internet = args.iter().any(|a| a == "--internet" || a == "--exit");

    if !cli_mode {
        ui::run_gui_with(init_server, init_token, init_internet);
        return;
    }

    if let Some(info) = api::check_update() {
        if info.force_update {
            eprintln!("[nexguard] mandatory update required: v{}", info.version);
            eprintln!("[nexguard] updating...");
            match api::self_update(&info.download_url) {
                Ok(()) => {
                    eprintln!("[nexguard] updated to v{}", info.version);
                    api::restart_self();
                }
                Err(e) => {
                    eprintln!("[nexguard] update failed: {}", e);
                    std::process::exit(1);
                }
            }
        } else if info.has_update {
            eprintln!("[nexguard] update available: v{}", info.version);
        }
    }

    let args = parse_args();

    eprintln!("[vpn-client] joining server {}...", args.server);

    let private_key = load_or_generate_key();
    let secret = StaticSecret::from(private_key);
    let public_key = PublicKey::from(&secret);
    let pub_key_b64 = b64_encode(public_key.as_bytes());

    eprintln!("[vpn-client] public key: {}", pub_key_b64);

    let join_resp = if let Some(ref url) = args.join_url {
        match api::join_via_api(url, &args.token, &pub_key_b64, &args.name) {
            Ok(r) => r,
            Err(e) => { eprintln!("[vpn-client] {}", e); std::process::exit(1); }
        }
    } else if args.advertise_routes.is_empty() {
        api::join_server(&args.server, args.control_port, &args.token, &pub_key_b64, &args.name)
    } else {
        eprintln!("[vpn-client] advertising routes: {:?}", args.advertise_routes);
        match api::try_join_server_with_routes(
            &args.server, args.control_port, &args.token, &pub_key_b64, &args.name, &args.advertise_routes,
        ) {
            Ok(r) => r,
            Err(e) => { eprintln!("[vpn-client] {}", e); std::process::exit(1); }
        }
    };

    let assigned_addr = join_resp.address.clone();
    let server_pub_key = b64_decode(&join_resp.server_public_key);

    eprintln!("[vpn-client] assigned address: {}", assigned_addr);

    let (ip, prefix) = parse_cidr(&assigned_addr);
    let server_endpoint = if args.relay.is_some() {
        let relay_host = args.relay.as_ref().unwrap().split(':').next().unwrap_or("127.0.0.1");
        format!("{}:51820", relay_host).parse().unwrap()
    } else if let Some(ref ep) = join_resp.server_endpoint {
        ep.parse().unwrap_or_else(|_| api::parse_endpoint(&args.server))
    } else {
        api::parse_endpoint(&args.server)
    };

    let tun_dev = tun::TunDevice::create(args.mtu);
    tun_dev.set_address(ip, prefix);

    if let Some(ref v6) = join_resp.address_v6 {
        if let Some((v6_ip, v6_prefix)) = parse_ipv6_cidr(v6) {
            tun_dev.set_address_v6(&v6_ip.to_string(), v6_prefix);
            eprintln!("[vpn-client] ipv6 address: {}", v6);
        }
    }

    tun_dev.set_up();

    if !args.internet {
        if prefix < 32 {
            let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
            let net = Ipv4Addr::from(u32::from(ip) & mask);
            let _ = route::add_route(net, prefix, tun_dev.name());
        }

        for peer in &join_resp.peers {
            if let Some(ips) = peer.get("allowed_ips").and_then(|v| v.as_array()) {
                for cidr_val in ips {
                    if let Some(cidr) = cidr_val.as_str() {
                        let (net_ip, net_prefix) = parse_cidr(cidr);
                        if net_ip != ip {
                            let _ = route::add_route(net_ip, net_prefix, tun_dev.name());
                        }
                    }
                }
            }
        }

        if let Some(ref network) = args.vpn_network {
            let (net_ip, net_prefix) = parse_cidr(network);
            let _ = route::add_route(net_ip, net_prefix, tun_dev.name());
            eprintln!("[vpn-client] added route {}", network);
        }
    }

    let exit_state = if args.internet {
        let wg_ip = server_endpoint.ip().to_string();
        let control_ip = if args.relay.is_some() {
            wg_ip.clone()
        } else {
            use std::net::ToSocketAddrs;
            let target = if args.server.contains(':') { args.server.clone() } else { format!("{}:9190", args.server) };
            target.to_socket_addrs().ok().and_then(|mut a| a.next()).map(|a| a.ip().to_string()).unwrap_or_else(|| wg_ip.clone())
        };
        let relay_ip = args.relay.as_ref()
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
            Ok(state) => {
                eprintln!("[vpn-client] internet routing enabled (v6={})", has_v6);
                Some(state)
            }
            Err(e) => {
                eprintln!("[vpn-client] internet setup failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    eprintln!(
        "[vpn-client] tun={}, addr={}, endpoint={}",
        tun_dev.name(),
        assigned_addr,
        server_endpoint,
    );

    let server_pub = PublicKey::from(server_pub_key);
    let tunn = Tunn::new(secret, server_pub, None, Some(25), 0, None);
    let tunnel = Mutex::new(wg::WgState { tunn, server_pub_key: server_pub });
    let rekey_key = Arc::new(Mutex::new(private_key));
    let rekey_ctx = wg::RekeyCtx {
        server: args.server.clone(),
        control_port: args.control_port,
        token: args.token.clone(),
        private_key: Arc::clone(&rekey_key),
    };
    let tx = AtomicU64::new(0);
    let rx = AtomicU64::new(0);

    let mesh_mgr = if join_resp.mesh.unwrap_or(false) {
        let mesh_port = args.listen_port.wrapping_add(1);
        let mgr = Arc::new(mesh::MeshManager::new(private_key, mesh_port));
        if let Some(ref peers) = join_resp.mesh_peers {
            let parsed = api::parse_mesh_peers(peers);
            mgr.update_peers(&parsed, &pub_key_b64);
        }
        eprintln!("[vpn-client] mesh mode enabled, port={}, peers={}",
            mesh_port,
            join_resp.mesh_peers.as_ref().map_or(0, |p| p.len()));

        let refresh_mgr = Arc::clone(&mgr);
        let refresh_server = args.server.clone();
        let refresh_port = args.control_port;
        let refresh_token = args.token.clone();
        let refresh_pub_key = pub_key_b64.clone();
        std::thread::spawn(move || {
            let interval = std::time::Duration::from_secs(30);
            loop {
                std::thread::sleep(interval);
                if SHUTDOWN.load(Ordering::Relaxed) { break; }
                let peers = api::get_mesh_peers(&refresh_server, refresh_port, &refresh_token);
                refresh_mgr.update_peers(&peers, &refresh_pub_key);
            }
        });
        Some(mgr)
    } else {
        None
    };

    let tun_name_for_cleanup = tun_dev.name().to_string();
    let has_internet = args.internet;
    std::panic::set_hook({
        let tun = tun_name_for_cleanup.clone();
        let internet = has_internet;
        Box::new(move |info| {
            eprintln!("[vpn-client] PANIC: {}", info);
            if internet { route::emergency_cleanup(&tun); }
        })
    });

    setup_signal_handler();

    let _kill_switch = if args.kill_switch {
        let server_ip = server_endpoint.ip().to_string();
        Some(route::KillSwitch::activate(tun_dev.name(), &[&server_ip]))
    } else {
        None
    };

    let tls_addr = format!("{}:{}", server_endpoint.ip(), OBFS_PORT);
    let relay_target = args.relay_name.as_deref().unwrap_or(&args.server).to_string();
    let mesh_ref = mesh_mgr.as_ref().map(|m| m.as_ref());

    let effective_relay = args.relay.clone();
    let relay_auth_token = args.token.clone();
    let mut backoff_ms: u64 = 1000;
    const MAX_BACKOFF_MS: u64 = 30_000;

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) { break; }

        let connected = if let Some(ref relay_addrs) = effective_relay {
            let relays: Vec<&str> = relay_addrs.split(',').map(|s| s.trim()).collect();
            let mut ok = false;
            for addr in &relays {
                if SHUTDOWN.load(Ordering::Relaxed) { break; }
                eprintln!("[vpn-client] trying relay {}...", addr);
                match wg::connect_relay(addr, &relay_target, &relay_auth_token) {
                    Ok(mut stream) => {
                        eprintln!("[vpn-client] relay connected via {}", addr);
                        ok = true;
                        wg::run_data_plane_tls(&tun_dev, &mut stream, &tunnel, &tx, &rx, &SHUTDOWN,
                            mesh_ref, Some(&rekey_ctx));
                        break;
                    }
                    Err(e) => eprintln!("[vpn-client] relay {} failed: {}", addr, e),
                }
            }
            if !ok && !SHUTDOWN.load(Ordering::Relaxed) {
                eprintln!("[vpn-client] relays failed, trying direct TLS...");
                if let Ok(mut s) = wg::connect_tls(&tls_addr) {
                    ok = true;
                    wg::run_data_plane_tls(&tun_dev, &mut s, &tunnel, &tx, &rx, &SHUTDOWN,
                        mesh_ref, Some(&rekey_ctx));
                }
            }
            ok
        } else {
            eprintln!("[vpn-client] connecting TLS to {}...", tls_addr);
            match wg::connect_tls(&tls_addr) {
                Ok(mut tls_stream) => {
                    eprintln!("[vpn-client] TLS connected");
                    wg::run_data_plane_tls(&tun_dev, &mut tls_stream, &tunnel, &tx, &rx, &SHUTDOWN,
                        mesh_ref, Some(&rekey_ctx));
                    true
                }
                Err(e) => {
                    eprintln!("[vpn-client] TLS failed: {}", e);
                    false
                }
            }
        };

        if SHUTDOWN.load(Ordering::Relaxed) { break; }

        if connected {
            backoff_ms = 1000;
            eprintln!("[vpn-client] disconnected, reconnecting in 1s...");
        } else {
            eprintln!("[vpn-client] reconnecting in {}s...", backoff_ms / 1000);
        }
        std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
    }

    eprintln!("[vpn-client] cleaning up routes...");
    drop(exit_state);
    drop(mesh_mgr);
    if has_internet {
        route::emergency_cleanup(&tun_name_for_cleanup);
    }
}

fn key_path() -> std::path::PathBuf {
    let dir = dirs_next().unwrap_or_else(|| std::path::PathBuf::from("."));
    dir.join("client.key")
}

fn dirs_next() -> Option<std::path::PathBuf> {
    let home = std::env::var("SUDO_USER").ok()
        .and_then(|u| {
            #[cfg(unix)]
            {
                let out = std::process::Command::new("sh")
                    .args(["-c", &format!("eval echo ~{}", u)])
                    .output().ok()?;
                let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if h.is_empty() || h.starts_with('~') { None } else { Some(h) }
            }
            #[cfg(not(unix))]
            { None }
        })
        .or_else(|| std::env::var("HOME").ok())
        .or_else(|| std::env::var("USERPROFILE").ok())?;
    let dir = std::path::PathBuf::from(home).join(".nexguard");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

pub fn load_or_generate_key() -> [u8; 32] {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let path = key_path();

    let try_load = |p: &std::path::Path| -> Option<[u8; 32]> {
        let data = std::fs::read_to_string(p).ok()?;
        let bytes = b64.decode(data.trim()).ok()?;
        if bytes.len() != 32 { return None; }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Some(key)
    };

    if let Some(key) = try_load(&path) {
        return key;
    }

    #[cfg(unix)]
    {
        let root_path = std::path::PathBuf::from("/var/root/.nexguard/client.key");
        if root_path != path {
            if let Some(key) = try_load(&root_path) {
                let _ = std::fs::write(&path, b64.encode(key));
                let _ = std::fs::remove_file(&root_path);
                return key;
            }
        }
    }

    let key = generate_private_key();
    let _ = std::fs::write(&path, b64.encode(key));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        fix_ownership(&path);
    }
    key
}

#[cfg(unix)]
fn fix_ownership(path: &std::path::Path) {
    if let Ok(user) = std::env::var("SUDO_USER") {
        let _ = std::process::Command::new("chown")
            .args([&user, &path.to_string_lossy().to_string()])
            .status();
        if let Some(dir) = path.parent() {
            let _ = std::process::Command::new("chown")
                .args([&user, &dir.to_string_lossy().to_string()])
                .status();
        }
    }
}

pub fn generate_private_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    #[cfg(unix)]
    {
        let fd = unsafe { libc::open(b"/dev/urandom\0".as_ptr() as *const _, libc::O_RDONLY) };
        if fd >= 0 {
            unsafe {
                libc::read(fd, key.as_mut_ptr() as *mut _, 32);
                libc::close(fd);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Security::Cryptography::*;
        unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                key.as_mut_ptr(),
                key.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            );
        }
    }
    key
}

pub fn b64_encode(d: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(d)
}

pub fn b64_decode(s: &str) -> [u8; 32] {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .expect("invalid base64");
    assert!(b.len() == 32, "key must be 32 bytes, got {}", b.len());
    let mut k = [0u8; 32];
    k.copy_from_slice(&b);
    k
}

pub fn parse_cidr(s: &str) -> (Ipv4Addr, u8) {
    let (ip, prefix) = s.split_once('/').unwrap_or_else(|| {
        eprintln!("[vpn-client] invalid CIDR: {}", s);
        std::process::exit(1);
    });
    let ip: Ipv4Addr = ip.parse().unwrap_or_else(|_| {
        eprintln!("[vpn-client] invalid IP in CIDR: {}", s);
        std::process::exit(1);
    });
    let prefix: u8 = prefix.parse().unwrap_or_else(|_| {
        eprintln!("[vpn-client] invalid prefix in CIDR: {}", s);
        std::process::exit(1);
    });
    (ip, prefix)
}

pub fn parse_ipv6_cidr(s: &str) -> Option<(std::net::Ipv6Addr, u8)> {
    let (ip_str, prefix_str) = s.split_once('/')?;
    let ip: std::net::Ipv6Addr = ip_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix > 128 { return None; }
    Some((ip, prefix))
}

fn setup_signal_handler() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_signal as *const () as libc::sighandler_t);
    }
}

#[cfg(unix)]
extern "C" fn handle_signal(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

struct Args {
    server: String,
    token: String,
    name: String,
    control_port: u16,
    listen_port: u16,
    mtu: usize,
    vpn_network: Option<String>,
    internet: bool,
    relay: Option<String>,
    relay_name: Option<String>,
    join_url: Option<String>,
    advertise_routes: Vec<String>,
    kill_switch: bool,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    let mut server = String::new();
    let mut token = String::new();
    let mut name = String::new();
    let mut control_port = 9190u16;
    let mut listen_port = 0u16;
    let mut mtu = 1420usize;
    let mut vpn_network = None;
    let mut internet = false;
    let mut relay = None;
    let mut advertise_routes = Vec::new();
    let mut kill_switch = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--server" | "-s" => { i += 1; if i < argv.len() { server = argv[i].clone(); } }
            "--token" | "-t" => { i += 1; if i < argv.len() { token = argv[i].clone(); } }
            "--name" | "-n" => { i += 1; if i < argv.len() { name = argv[i].clone(); } }
            "--relay" | "-r" => { i += 1; if i < argv.len() { relay = Some(argv[i].clone()); } }
            "--control-port" => { i += 1; if i < argv.len() { control_port = argv[i].parse().unwrap_or(9190); } }
            "--listen-port" => { i += 1; if i < argv.len() { listen_port = argv[i].parse().unwrap_or(0); } }
            "--mtu" => { i += 1; if i < argv.len() { mtu = argv[i].parse().unwrap_or(1420); } }
            "--vpn-network" | "--network" => { i += 1; if i < argv.len() { vpn_network = Some(argv[i].clone()); } }
            "--advertise-routes" | "--routes" => {
                i += 1;
                if i < argv.len() {
                    advertise_routes = argv[i].split(',').map(|s| s.trim().to_string()).collect();
                }
            }
            "--internet" | "--exit" => { internet = true; }
            "--kill-switch" | "--killswitch" => { kill_switch = true; }
            "--gui" | "--cli" | "--no-gui" => {}
            "--version" | "-v" => {
                eprintln!("nexguard {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                eprintln!("Usage: nexguard [OPTIONS]");
                eprintln!("");
                eprintln!("  nexguard                              Open GUI (default)");
                eprintln!("  nexguard --server IP --token TOKEN    Open GUI with server pre-filled");
                eprintln!("  nexguard --cli --server IP --token T  CLI mode (no GUI)");
                eprintln!("");
                eprintln!("Options:");
                eprintln!("  -s, --server IP:PORT      VPN server address");
                eprintln!("  -t, --token TOKEN         Auth token");
                eprintln!("  -n, --name NAME           Client name");
                eprintln!("  -r, --relay IP:443        Relay server (tunnel through nexguard relay)");
                eprintln!("  --internet                Route all traffic through VPN");
                eprintln!("  --cli, --no-gui           Force CLI mode");
                eprintln!("  --gui                     Force GUI mode");
                std::process::exit(0);
            }
            _ => {
                if server.is_empty() {
                    server = argv[i].clone();
                }
            }
        }
        i += 1;
    }

    if server.is_empty() { server = std::env::var("VPN_SERVER").unwrap_or_default(); }
    if token.is_empty() { token = std::env::var("VPN_TOKEN").unwrap_or_default(); }
    if name.is_empty() { name = generate_client_name(); }

    let mut relay_name: Option<String> = None;
    let mut join_url: Option<String> = None;

    if server.is_empty() && !token.is_empty() {
        eprintln!("[nexguard] resolving server from token...");
        match crate::api::fetch_connect_info(&token) {
            Some(info) => {
                join_url = info.join_url;
                if let Some(s) = info.server {
                    server = s;
                } else if let Some(r) = info.relay {
                    relay = Some(r.clone());
                    relay_name = info.relay_name;
                    server = r.split(':').next().unwrap_or(&r).to_string();
                }
            }
            None => {
                eprintln!("Error: could not resolve server from token");
                std::process::exit(1);
            }
        }
    }

    if server.is_empty() && join_url.is_none() {
        eprintln!("Error: --server or --token required");
        std::process::exit(1);
    }
    if server.is_empty() { server = "api-proxy".to_string(); }

    if relay.is_none() { relay = std::env::var("VPN_RELAY").ok(); }

    Args { server, token, name, control_port, listen_port, mtu, vpn_network, internet, relay, relay_name, join_url, advertise_routes, kill_switch }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

pub fn generate_client_name() -> String {
    std::env::var("VPN_NAME").unwrap_or_else(|_| {
        let id_path = dirs_next()
            .map(|d| d.join("device-id"))
            .unwrap_or_else(|| std::path::PathBuf::from(".nexguard-device-id"));

        if let Ok(id) = std::fs::read_to_string(&id_path) {
            let id = id.trim().to_string();
            if !id.is_empty() { return id; }
        }

        #[cfg(unix)]
        {
            let root_id = std::path::PathBuf::from("/var/root/.nexguard/device-id");
            if root_id != id_path {
                if let Ok(id) = std::fs::read_to_string(&root_id) {
                    let id = id.trim().to_string();
                    if !id.is_empty() {
                        let _ = std::fs::write(&id_path, &id);
                        let _ = std::fs::remove_file(&root_id);
                        return id;
                    }
                }
            }
        }

        let hostname = get_hostname();
        let os_name = if cfg!(target_os = "macos") { "mac" }
            else if cfg!(target_os = "windows") { "win" }
            else { "linux" };

        let mut seed = [0u8; 4];
        #[cfg(unix)]
        {
            let fd = unsafe { libc::open(b"/dev/urandom\0".as_ptr() as *const _, libc::O_RDONLY) };
            if fd >= 0 {
                unsafe { libc::read(fd, seed.as_mut_ptr() as *mut _, 4); libc::close(fd); }
            }
        }
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Security::Cryptography::*;
            unsafe { BCryptGenRandom(std::ptr::null_mut(), seed.as_mut_ptr(), 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG); }
        }

        let name = format!("{}-{}-{:02x}{:02x}", hostname, os_name, seed[0], seed[1]);
        let _ = std::fs::write(&id_path, &name);
        #[cfg(unix)]
        fix_ownership(&id_path);
        name
    })
}

fn get_hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
        if ret == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let h = String::from_utf8_lossy(&buf[..end]).to_string();
            if !h.is_empty() { return h; }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(h) = std::env::var("COMPUTERNAME") { return h; }
    }
    "device".to_string()
}
