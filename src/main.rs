use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

const MAX_PACKET: usize = 65535;
const TIMER_TICK_MS: u64 = 250;

fn main() {
    let args = parse_args();

    eprintln!("[vpn-client] joining server {}...", args.server);

    let private_key = generate_private_key();
    let secret = StaticSecret::from(private_key);
    let public_key = PublicKey::from(&secret);
    let pub_key_b64 = b64_encode(public_key.as_bytes());

    eprintln!("[vpn-client] public key: {}", pub_key_b64);

    let join_resp = join_server(&args, &pub_key_b64);
    let assigned_addr = join_resp.address.clone();
    let server_pub_key = b64_decode(&join_resp.server_public_key);

    eprintln!("[vpn-client] assigned address: {}", assigned_addr);

    let (ip, prefix) = parse_cidr(&assigned_addr);
    let server_endpoint: SocketAddr = parse_endpoint(&args.server);

    let mtu = args.mtu;
    let tun = TunDevice::create(mtu);
    tun.set_address(ip, prefix);
    tun.set_up();

    if prefix < 32 {
        let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
        let net = Ipv4Addr::from(u32::from(ip) & mask);
        let _ = tun.add_route(net, prefix, ip);
    }

    for peer in &join_resp.peers {
        if let Some(ips) = peer.get("allowed_ips").and_then(|v| v.as_array()) {
            for cidr_val in ips {
                if let Some(cidr) = cidr_val.as_str() {
                    let (net_ip, net_prefix) = parse_cidr(cidr);
                    if net_ip != ip {
                        let _ = tun.add_route(net_ip, net_prefix, ip);
                    }
                }
            }
        }
    }

    if let Some(ref network) = args.vpn_network {
        let (net_ip, net_prefix) = parse_cidr(network);
        let _ = tun.add_route(net_ip, net_prefix, ip);
        eprintln!("[vpn-client] added route {}", network);
    }

    let udp = UdpSocket::bind(format!("0.0.0.0:{}", args.listen_port))
        .expect("failed to bind UDP");
    udp.set_nonblocking(true).ok();

    eprintln!("[vpn-client] tun={}, addr={}, endpoint={}, udp=:{}",
        tun.name(), assigned_addr, server_endpoint, args.listen_port);

    let tunn = Tunn::new(secret, PublicKey::from(server_pub_key), None, Some(25), 0, None);
    let tunnel = Mutex::new(WgState { tunn, endpoint: server_endpoint });
    let tx = AtomicU64::new(0);
    let rx = AtomicU64::new(0);

    setup_signal_handler();
    run_data_plane(&tun, &udp, &tunnel, &tx, &rx);
}

struct WgState { tunn: Tunn, endpoint: SocketAddr }

fn run_data_plane(tun: &TunDevice, udp: &UdpSocket, tunnel: &Mutex<WgState>, tx: &AtomicU64, rx: &AtomicU64) {
    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut udp_buf = vec![0u8; MAX_PACKET];
    let mut enc_buf = vec![0u8; MAX_PACKET];
    let mut dec_buf = vec![0u8; MAX_PACKET];
    let mut last_tick = std::time::Instant::now();
    let mut last_stats = std::time::Instant::now();

    loop {
        if unsafe { SHUTDOWN } { break; }
        let mut did_work = false;

        match tun.read_packet(&mut tun_buf) {
            Ok(n) if n > 0 => {
                did_work = true;
                let mut wg = tunnel.lock().unwrap();
                if let TunnResult::WriteToNetwork(data) = wg.tunn.encapsulate(&tun_buf[..n], &mut enc_buf) {
                    let _ = udp.send_to(data, wg.endpoint);
                    tx.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
            _ => {}
        }

        match udp.recv_from(&mut udp_buf) {
            Ok((n, _)) => {
                did_work = true;
                let mut wg = tunnel.lock().unwrap();
                match wg.tunn.decapsulate(None, &udp_buf[..n], &mut dec_buf) {
                    TunnResult::WriteToTunnelV4(data, _) => {
                        let _ = tun.write_packet(data);
                        rx.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    TunnResult::WriteToNetwork(data) => {
                        let _ = udp.send_to(data, wg.endpoint);
                        loop {
                            match wg.tunn.decapsulate(None, &[], &mut dec_buf) {
                                TunnResult::WriteToNetwork(data) => { let _ = udp.send_to(data, wg.endpoint); }
                                TunnResult::WriteToTunnelV4(data, _) => { let _ = tun.write_packet(data); rx.fetch_add(n as u64, Ordering::Relaxed); break; }
                                _ => break,
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }

        if last_tick.elapsed().as_millis() >= TIMER_TICK_MS as u128 {
            last_tick = std::time::Instant::now();
            let mut wg = tunnel.lock().unwrap();
            if let TunnResult::WriteToNetwork(data) = wg.tunn.update_timers(&mut enc_buf) {
                let _ = udp.send_to(data, wg.endpoint);
            }
        }

        if last_stats.elapsed().as_secs() >= 30 {
            last_stats = std::time::Instant::now();
            eprintln!("[vpn-client] tx={} rx={}", fmt_bytes(tx.load(Ordering::Relaxed)), fmt_bytes(rx.load(Ordering::Relaxed)));
        }

        if !did_work { std::thread::sleep(std::time::Duration::from_micros(100)); }
    }
    eprintln!("[vpn-client] shutdown");
}

// --- TUN device (Linux) ---

struct TunDevice { fd: i32, name: String }

impl TunDevice {
    fn create(mtu: usize) -> Self {
        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
        if fd < 0 { panic!("failed to open /dev/net/tun: {}", std::io::Error::last_os_error()); }
        #[repr(C)] struct IfReq { ifr_name: [u8; 16], ifr_flags: i16, _pad: [u8; 22] }
        let mut ifr = IfReq { ifr_name: [0u8; 16], ifr_flags: (libc::IFF_TUN | libc::IFF_NO_PI) as i16, _pad: [0u8; 22] };
        if unsafe { libc::ioctl(fd, 0x400454CA, &mut ifr as *mut _) } < 0 {
            unsafe { libc::close(fd); }
            panic!("TUNSETIFF failed: {}", std::io::Error::last_os_error());
        }
        let name_end = ifr.ifr_name.iter().position(|&b| b == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&ifr.ifr_name[..name_end]).into_owned();
        set_mtu(&name, mtu);
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 { unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK); } }
        Self { fd, name }
    }
    fn set_address(&self, ip: Ipv4Addr, prefix: u8) {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 { return; }
        let mut ifr = [0u8; 40];
        let nb = self.name.as_bytes();
        ifr[..nb.len().min(15)].copy_from_slice(&nb[..nb.len().min(15)]);
        let o = ip.octets();
        ifr[16] = libc::AF_INET as u8; ifr[20] = o[0]; ifr[21] = o[1]; ifr[22] = o[2]; ifr[23] = o[3];
        unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as _, &ifr as *const _); }
        let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
        let m = mask.to_be_bytes();
        ifr[20] = m[0]; ifr[21] = m[1]; ifr[22] = m[2]; ifr[23] = m[3];
        unsafe { libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &ifr as *const _); libc::close(sock); }
    }
    fn set_up(&self) {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 { return; }
        let mut ifr = [0u8; 40];
        let nb = self.name.as_bytes();
        ifr[..nb.len().min(15)].copy_from_slice(&nb[..nb.len().min(15)]);
        unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr as *mut _); }
        let flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
        let new = flags | libc::IFF_UP as i16 | libc::IFF_RUNNING as i16;
        ifr[16..18].copy_from_slice(&new.to_ne_bytes());
        unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr as *const _); libc::close(sock); }
    }
    fn add_route(&self, net: Ipv4Addr, prefix: u8, _via: Ipv4Addr) -> std::io::Result<()> {
        let s = std::process::Command::new("ip").args(["route", "add", &format!("{}/{}", net, prefix), "dev", &self.name]).status()?;
        if !s.success() { return Err(std::io::Error::other("ip route add failed")); }
        Ok(())
    }
    fn read_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(n as usize)
    }
    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const _, buf.len()) };
        if n < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(n as usize)
    }
    fn name(&self) -> &str { &self.name }
}

impl Drop for TunDevice { fn drop(&mut self) { unsafe { libc::close(self.fd); } } }

fn set_mtu(name: &str, mtu: usize) {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 { return; }
    #[repr(C)] struct R { n: [u8; 16], m: i32, _p: [u8; 20] }
    let mut r = R { n: [0; 16], m: mtu as i32, _p: [0; 20] };
    let nb = name.as_bytes();
    r.n[..nb.len().min(15)].copy_from_slice(&nb[..nb.len().min(15)]);
    unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as _, &r as *const _); libc::close(sock); }
}

// --- Control API ---

#[derive(serde::Deserialize)]
struct JoinResponse { address: String, server_public_key: String, #[allow(dead_code)] peers: Vec<serde_json::Value> }

fn join_server(args: &Args, pub_key_b64: &str) -> JoinResponse {
    let host = control_host(args);
    let body = format!(r#"{{"public_key":"{}","name":"{}"}}"#, pub_key_b64, args.name);
    let req = format!("POST /api/v1/join HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", host, args.token, body.len(), body);
    let resp = http_request(&host, &req);
    let body_start = resp.find("\r\n\r\n").expect("invalid response") + 4;
    serde_json::from_str(&resp[body_start..]).unwrap_or_else(|e| { eprintln!("[vpn-client] join failed: {} — {}", e, &resp[body_start..]); std::process::exit(1); })
}

fn http_request(host: &str, request: &str) -> String {
    let mut s = std::net::TcpStream::connect_timeout(&host.parse().expect("invalid addr"), std::time::Duration::from_secs(10)).unwrap_or_else(|e| { eprintln!("[vpn-client] connect {}: {}", host, e); std::process::exit(1); });
    s.write_all(request.as_bytes()).expect("write failed");
    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    let mut r = String::new();
    s.read_to_string(&mut r).ok();
    r
}

fn control_host(args: &Args) -> String {
    let a: SocketAddr = args.server.parse().expect("invalid server");
    format!("{}:{}", a.ip(), args.control_port)
}

fn parse_endpoint(server: &str) -> SocketAddr {
    let a: SocketAddr = server.parse().expect("invalid server");
    SocketAddr::new(a.ip(), 51820)
}

// --- Helpers ---

fn generate_private_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let fd = unsafe { libc::open(b"/dev/urandom\0".as_ptr() as *const _, libc::O_RDONLY) };
    if fd >= 0 { unsafe { libc::read(fd, key.as_mut_ptr() as *mut _, 32); libc::close(fd); } }
    key
}

fn b64_encode(d: &[u8]) -> String { use base64::Engine; base64::engine::general_purpose::STANDARD.encode(d) }

fn b64_decode(s: &str) -> [u8; 32] {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.decode(s.trim()).expect("invalid base64");
    let mut k = [0u8; 32]; k[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]); k
}

fn parse_cidr(s: &str) -> (Ipv4Addr, u8) {
    let (ip, prefix) = s.split_once('/').expect("invalid CIDR");
    (ip.parse().expect("invalid IP"), prefix.parse().expect("invalid prefix"))
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 { format!("{}B", b) } else if b < 1048576 { format!("{:.1}KB", b as f64 / 1024.0) } else { format!("{:.1}MB", b as f64 / 1048576.0) }
}

static mut SHUTDOWN: bool = false;
fn setup_signal_handler() {
    unsafe {
        libc::signal(libc::SIGINT, handle_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_signal as libc::sighandler_t);
    }
}
extern "C" fn handle_signal(_: libc::c_int) { unsafe { SHUTDOWN = true; } }

// --- CLI ---

struct Args { server: String, token: String, name: String, control_port: u16, listen_port: u16, mtu: usize, vpn_network: Option<String> }

fn parse_args() -> Args {
    let a: Vec<String> = std::env::args().collect();
    let (mut server, mut token, mut name, mut cp, mut lp, mut mtu, mut vn) = (String::new(), String::new(), String::new(), 9190u16, 0u16, 1420usize, None);
    let mut i = 1;
    while i < a.len() {
        match a[i].as_str() {
            "--server" | "-s" => { i += 1; if i < a.len() { server = a[i].clone(); } }
            "--token" | "-t" => { i += 1; if i < a.len() { token = a[i].clone(); } }
            "--name" | "-n" => { i += 1; if i < a.len() { name = a[i].clone(); } }
            "--control-port" => { i += 1; if i < a.len() { cp = a[i].parse().unwrap_or(9190); } }
            "--listen-port" => { i += 1; if i < a.len() { lp = a[i].parse().unwrap_or(0); } }
            "--mtu" => { i += 1; if i < a.len() { mtu = a[i].parse().unwrap_or(1420); } }
            "--vpn-network" | "--network" => { i += 1; if i < a.len() { vn = Some(a[i].clone()); } }
            "--help" | "-h" => {
                eprintln!("Usage: vpn-client [OPTIONS]");
                eprintln!("  -s, --server IP:PORT     VPN server");
                eprintln!("  -t, --token TOKEN        Auth token");
                eprintln!("  -n, --name NAME          Client name");
                eprintln!("  --control-port PORT       Control API port (default: 9190)");
                eprintln!("  --vpn-network CIDR       Server VPN network route");
                std::process::exit(0);
            }
            _ => { if server.is_empty() { server = a[i].clone(); } }
        }
        i += 1;
    }
    if server.is_empty() { server = std::env::var("VPN_SERVER").unwrap_or_default(); }
    if token.is_empty() { token = std::env::var("VPN_TOKEN").unwrap_or_default(); }
    if name.is_empty() { name = std::env::var("VPN_NAME").unwrap_or_else(|_| { let mut b = [0u8; 4]; let fd = unsafe { libc::open(b"/dev/urandom\0".as_ptr() as *const _, libc::O_RDONLY) }; if fd >= 0 { unsafe { libc::read(fd, b.as_mut_ptr() as *mut _, 4); libc::close(fd); } } format!("client-{:02x}{:02x}", b[0], b[1]) }); }
    if server.is_empty() { eprintln!("Error: --server required"); std::process::exit(1); }
    Args { server, token, name, control_port: cp, listen_port: lp, mtu, vpn_network: vn }
}
