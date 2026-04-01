mod api;
pub mod mesh;
mod route;
pub mod tun;
mod ui;
mod vpn;
mod wg;

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let gui_mode = args.iter().any(|a| a == "--gui")
        || (args.len() == 1 && std::env::var("VPN_SERVER").is_err());

    if gui_mode {
        ui::run_gui();
        return;
    }

    std::thread::spawn(|| {
        if let Some(info) = api::check_update() {
            if info.has_update {
                eprintln!("[nexguard] update available: v{} — {}", info.version, info.download_url);
            }
        }
    });

    let args = parse_args();

    eprintln!("[vpn-client] joining server {}...", args.server);

    let private_key = generate_private_key();
    let secret = StaticSecret::from(private_key);
    let public_key = PublicKey::from(&secret);
    let pub_key_b64 = b64_encode(public_key.as_bytes());

    eprintln!("[vpn-client] public key: {}", pub_key_b64);

    let join_resp = api::join_server(
        &args.server,
        args.control_port,
        &args.token,
        &pub_key_b64,
        &args.name,
    );

    let assigned_addr = join_resp.address.clone();
    let server_pub_key = b64_decode(&join_resp.server_public_key);

    eprintln!("[vpn-client] assigned address: {}", assigned_addr);

    let (ip, prefix) = parse_cidr(&assigned_addr);
    let server_endpoint = if let Some(ref ep) = join_resp.server_endpoint {
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
        let control_ip = {
            use std::net::ToSocketAddrs;
            let target = if args.server.contains(':') { args.server.clone() } else { format!("{}:9190", args.server) };
            target.to_socket_addrs().ok().and_then(|mut a| a.next()).map(|a| a.ip().to_string()).unwrap_or_else(|| wg_ip.clone())
        };
        let mut preserve_ips: Vec<&str> = vec![&wg_ip];
        if control_ip != wg_ip {
            preserve_ips.push(&control_ip);
        }
        let vpn_net = join_resp.vpn_network.as_deref()
            .or(args.vpn_network.as_deref());
        let has_v6 = join_resp.vpn_network_v6.is_some();
        match route::ExitRouteState::setup_dual(&preserve_ips, tun_dev.name(), vpn_net, has_v6) {
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

    let udp = UdpSocket::bind(format!("0.0.0.0:{}", args.listen_port))
        .expect("failed to bind UDP");
    udp.set_nonblocking(true).ok();

    eprintln!(
        "[vpn-client] tun={}, addr={}, endpoint={}, udp=:{}",
        tun_dev.name(),
        assigned_addr,
        server_endpoint,
        args.listen_port
    );

    let tunn = Tunn::new(secret, PublicKey::from(server_pub_key), None, Some(25), 0, None);
    let tunnel = Mutex::new(wg::WgState {
        tunn,
        endpoint: server_endpoint,
    });
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

    setup_signal_handler();
    wg::run_data_plane(&tun_dev, &udp, &tunnel, &tx, &rx, &SHUTDOWN,
        mesh_mgr.as_ref().map(|m| m.as_ref()));

    drop(exit_state);
    drop(mesh_mgr);
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
    let mut k = [0u8; 32];
    let len = b.len().min(32);
    k[..len].copy_from_slice(&b[..len]);
    k
}

pub fn parse_cidr(s: &str) -> (Ipv4Addr, u8) {
    let (ip, prefix) = s.split_once('/').expect("invalid CIDR");
    (ip.parse().expect("invalid IP"), prefix.parse().expect("invalid prefix"))
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
        libc::signal(libc::SIGINT, handle_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_signal as libc::sighandler_t);
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

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--server" | "-s" => { i += 1; if i < argv.len() { server = argv[i].clone(); } }
            "--token" | "-t" => { i += 1; if i < argv.len() { token = argv[i].clone(); } }
            "--name" | "-n" => { i += 1; if i < argv.len() { name = argv[i].clone(); } }
            "--control-port" => { i += 1; if i < argv.len() { control_port = argv[i].parse().unwrap_or(9190); } }
            "--listen-port" => { i += 1; if i < argv.len() { listen_port = argv[i].parse().unwrap_or(0); } }
            "--mtu" => { i += 1; if i < argv.len() { mtu = argv[i].parse().unwrap_or(1420); } }
            "--vpn-network" | "--network" => { i += 1; if i < argv.len() { vpn_network = Some(argv[i].clone()); } }
            "--internet" | "--exit" => { internet = true; }
            "--gui" => {}
            "--help" | "-h" => {
                eprintln!("Usage: vpn-client [OPTIONS]");
                eprintln!("  -s, --server IP:PORT      VPN server");
                eprintln!("  -t, --token TOKEN         Auth token");
                eprintln!("  -n, --name NAME           Client name");
                eprintln!("  --control-port PORT        Control API port (default: 9190)");
                eprintln!("  --vpn-network CIDR        Server VPN network route");
                eprintln!("  --internet               Route all traffic through VPN");
                eprintln!("  --gui                    Launch native GUI");
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
    if server.is_empty() {
        eprintln!("Error: --server required");
        std::process::exit(1);
    }

    Args { server, token, name, control_port, listen_port, mtu, vpn_network, internet }
}

pub fn generate_client_name() -> String {
    std::env::var("VPN_NAME").unwrap_or_else(|_| {
        let mut b = [0u8; 4];
        #[cfg(unix)]
        {
            let fd = unsafe { libc::open(b"/dev/urandom\0".as_ptr() as *const _, libc::O_RDONLY) };
            if fd >= 0 {
                unsafe {
                    libc::read(fd, b.as_mut_ptr() as *mut _, 4);
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
                    b.as_mut_ptr(),
                    b.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                );
            }
        }
        format!("client-{:02x}{:02x}", b[0], b[1])
    })
}
