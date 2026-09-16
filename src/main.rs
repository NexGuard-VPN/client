#![cfg_attr(not(feature = "gui"), allow(dead_code))]
mod api;
pub mod cli;
pub mod autostart;
pub mod control;
pub mod engine;
pub mod protocol;
pub mod service;
#[cfg(feature = "gui")]
mod modal;
mod derp;
mod derpframe;
mod dial;
mod disco;
mod dns;
pub mod exitnode;
mod meshapi;
mod meshtypes;
pub mod meshnet;
pub mod path;
pub mod allowed;
pub mod rng;
pub mod netmon;
mod profiles;
mod route;
mod stun;
#[cfg(feature = "gui")]
pub mod tray;
pub mod tun;
#[cfg(feature = "gui")]
mod ui;

use cli::{arg_value, join_token};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn print_help() {
    println!("Usage: nexguard [OPTIONS]");
    println!();
    println!("  nexguard                              Open the app (default)");
    println!("  nexguard join TOKEN                   Join a project with a token from the dashboard");
    println!("  nexguard --mesh --share-internet      Run headless as an exit node");
    println!();
    println!("Options:");
    println!("  -n, --name NAME           This device's name in the project");
    println!("  -t, --token TOKEN         Account token (defaults to the signed-in one)");
    println!("  --login                   Sign in to your NexGuard account (headless)");
    println!("  --mesh                    Join the project network (headless)");
    println!("  --join-mesh TOKEN         Accept an invite, then join that project");
    println!("  --join-token TOKEN        Join with a project token, without signing in");
    println!("  --list-networks           Print the project networks this account can join");
    println!("  --network NETWORK_ID      Join a specific project network");
    println!("  --exit-node DEVICE_ID     Route all traffic through that device");
    println!("  --share-internet          Let other devices exit through this one");
    println!("  --magic-dns               Resolve device names (changes system DNS)");
    println!("  --advertise-routes CIDRS  Comma-separated subnets to share");
    println!("  --cleanup                 Remove stale routes from a crashed session");
    println!("  --daemon                  Wait for the app to ask for a tunnel (used by the boot service)");
    println!("  --status                  Print what the running daemon is doing");
    println!("  --install-service         Start automatically on boot (needs root)");
    println!("  --uninstall-service       Remove the boot service");
    println!("  -v, --version             Print version and exit");
    println!("  -h, --help                Print this help and exit");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("nexguard {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    eprintln!(
        "[nexguard] v{} ({}-{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );

    if args.iter().any(|a| a == service::INSTALL_FLAG) {
        if join_token(&args).is_some() {
            join_project(&args);
        }
        service::install(&args);
        return;
    }
    if args.iter().any(|a| a == service::UNINSTALL_FLAG) {
        service::uninstall();
        return;
    }
    if args.iter().any(|a| a == "--status") {
        print_status();
        return;
    }
    if args.iter().any(|a| a == cli::DAEMON_FLAG) {
        run_daemon(None);
        return;
    }
    if args.iter().any(|a| a == "--cleanup") {
        route::cleanup_stale_session();
        return;
    }

    route::restore_orphaned_dns();

    if args.iter().any(|a| a == "--login") {
        run_login();
        return;
    }
    if args.iter().any(|a| a == "--list-networks") {
        list_networks(&args);
        return;
    }
    if args.iter().any(|a| a == cli::MESH_FLAG) || join_token(&args).is_some() {
        run_mesh(&args);
        return;
    }

    #[cfg(feature = "gui")]
    ui::run_gui();
    #[cfg(not(feature = "gui"))]
    {
        eprintln!("[nexguard] this build has no interface; use --mesh");
        print_help();
    }
}

const KEY_FILE: &str = "client.key";

fn key_path() -> std::path::PathBuf {
    let dir = dirs_next().unwrap_or_else(|| std::path::PathBuf::from("."));
    dir.join(KEY_FILE)
}

/// Before the daemon existed the app ran elevated but kept its key and
/// identity in the signed-in user's directory. The first daemon run adopts
/// them, so the machine keeps its address instead of enrolling as a new device.
#[cfg(unix)]
fn adopt_operator_identity() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Some(own) = dirs_next() else { return };
    let files = [KEY_FILE, meshapi::IDENTITY_FILE];
    if files.iter().any(|f| own.join(f).exists()) {
        return;
    }
    let operator = std::env::var(control::OPERATOR_UID_ENV)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .or_else(control::console_uid)
        .filter(|uid| *uid != 0);
    let Some(theirs) = operator.and_then(profiles::user_config_dir) else { return };
    for file in files {
        let source = theirs.join(file);
        if !source.exists() {
            continue;
        }
        let target = own.join(file);
        if std::fs::copy(&source, &target).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600));
            eprintln!("[nexguard] adopted {} from {}", file, theirs.display());
        }
    }
}

pub fn dirs_next() -> Option<std::path::PathBuf> {
    profiles::config_dir()
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
        secure_key_file(&path);
        return key;
    }

    #[cfg(unix)]
    {
        let root_path = std::path::PathBuf::from(LEGACY_ROOT_KEY);
        if root_path != path {
            if let Some(key) = try_load(&root_path) {
                let _ = std::fs::write(&path, b64.encode(key));
                secure_key_file(&path);
                let _ = std::fs::remove_file(&root_path);
                return key;
            }
        }
    }

    let key = generate_private_key();
    let _ = std::fs::write(&path, b64.encode(key));
    secure_key_file(&path);
    key
}

#[cfg(unix)]
const LEGACY_ROOT_KEY: &str = "/var/root/.nexguard/client.key";

fn secure_key_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        fix_ownership(path);
    }
    #[cfg(not(unix))]
    let _ = path;
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
    rng::fill(&mut key);
    key
}

pub fn b64_encode(d: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(d)
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

const MESH_POLL: std::time::Duration = std::time::Duration::from_millis(500);
const LOGIN_POLL: std::time::Duration = std::time::Duration::from_secs(2);
const LOGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

fn run_login() {
    let request = match api::request_account_login() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[nexguard] sign-in failed: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("[nexguard] open this link in a browser and confirm:");
    println!("{}", request.login_url);
    eprintln!("[nexguard] waiting...");

    let deadline = std::time::Instant::now() + LOGIN_TIMEOUT;
    while std::time::Instant::now() < deadline {
        match api::poll_account_login(&request.token) {
            Ok(Some(_)) => {
                let who = api::account_email().unwrap_or_default();
                if who.is_empty() {
                    eprintln!("[nexguard] signed in");
                } else {
                    eprintln!("[nexguard] signed in as {}", who);
                }
                return;
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("[nexguard] sign-in failed: {}", e);
                std::process::exit(1);
            }
        }
        std::thread::sleep(LOGIN_POLL);
    }
    eprintln!("[nexguard] sign-in timed out");
    std::process::exit(1);
}

fn list_networks(argv: &[String]) {
    let token = arg_value(argv, "--token")
        .or_else(|| arg_value(argv, "-t"))
        .or_else(api::load_account_token)
        .unwrap_or_default();
    if token.is_empty() {
        eprintln!("[nexguard] mesh: sign in first, or pass --token");
        std::process::exit(1);
    }
    match meshapi::networks(&token) {
        Ok(networks) if networks.is_empty() => {
            println!("No mesh networks yet. Start one with --mesh, or accept an invite with --join-mesh.");
        }
        Ok(networks) => {
            for network in networks {
                println!(
                    "{}  {}  {}  {} device(s)  [{}]",
                    network.id, network.cidr, network.dns_suffix, network.device_count, network.role
                );
            }
        }
        Err(e) => {
            eprintln!("[nexguard] mesh: {}", e);
            std::process::exit(1);
        }
    }
}

fn account_token(argv: &[String]) -> String {
    arg_value(argv, "--token")
        .or_else(|| arg_value(argv, "-t"))
        .or_else(api::load_account_token)
        .unwrap_or_default()
}

fn mesh_config(argv: &[String], user_token: String, network_id: Option<String>) -> meshnet::MeshConfig {
    meshnet::MeshConfig {
        user_token,
        join_token: join_token(argv),
        network_id,
        device_name: arg_value(argv, "--name")
            .or_else(|| arg_value(argv, "-n"))
            .unwrap_or_else(generate_client_name),
        exit_node: arg_value(argv, "--exit-node"),
        advertise_exit_node: argv.iter().any(|a| a == "--share-internet"),
        manage_dns: argv.iter().any(|a| a == "--magic-dns"),
        advertise_routes: arg_value(argv, "--advertise-routes")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default(),
        ..Default::default()
    }
}

/// Redeems the join token now, while the person is watching, so a bad or
/// revoked token fails here rather than in a service log nobody reads.
fn join_project(argv: &[String]) {
    let config = mesh_config(argv, String::new(), arg_value(argv, "--network"));
    match meshnet::enroll(&config) {
        Ok(identity) => eprintln!(
            "[nexguard] joined {} as {} ({})",
            identity.network.dns_suffix, config.device_name, identity.mesh_ip
        ),
        Err(e) => {
            eprintln!("[nexguard] join: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_mesh(argv: &[String]) {
    let user_token = account_token(argv);

    let mut network_id = arg_value(argv, "--network");
    if let Some(invite) = arg_value(argv, "--join-mesh") {
        if user_token.is_empty() {
            eprintln!("[nexguard] mesh: sign in first, or pass --token");
            std::process::exit(1);
        }
        match meshapi::accept_invite(&user_token, &invite) {
            Ok(accepted) => {
                eprintln!(
                    "[nexguard] joined {} as {}",
                    accepted.network.dns_suffix, accepted.role
                );
                network_id = Some(accepted.network.id);
                meshapi::clear_identity();
            }
            Err(e) => {
                eprintln!("[nexguard] mesh: {}", e);
                std::process::exit(1);
            }
        }
    }

    run_daemon(Some(mesh_config(argv, user_token, network_id)));
}

/// One process shape for every unattended run: an engine, a control socket
/// for the app or `--status`, and optionally a tunnel brought up right away.
fn run_daemon(autoconnect: Option<meshnet::MeshConfig>) {
    setup_signal_handler();
    #[cfg(unix)]
    adopt_operator_identity();
    let engine = engine::Engine::new();
    #[cfg(unix)]
    {
        let served = Arc::clone(&engine);
        let socket_required = autoconnect.is_none();
        std::thread::spawn(move || {
            if let Err(e) = control::serve(served) {
                eprintln!("[nexguard] control socket: {}", e);
                if socket_required {
                    std::process::exit(1);
                }
            }
        });
    }

    if let Some(config) = autoconnect {
        match engine.connect(config) {
            Ok(snapshot) => announce(&snapshot),
            Err(e) => {
                eprintln!("[nexguard] mesh: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("[nexguard] daemon ready");
    }

    let headless = autoconnect_headless();
    while !SHUTDOWN.load(Ordering::Relaxed)
        && !control::RESTART_REQUESTED.load(Ordering::Relaxed)
    {
        if headless && engine.snapshot().state != protocol::EngineState::Connected {
            break;
        }
        std::thread::sleep(MESH_POLL);
    }
    engine.disconnect();
    eprintln!("[nexguard] mesh stopped");
}

fn autoconnect_headless() -> bool {
    std::env::args().any(|a| a == cli::MESH_FLAG) || join_token(&std::env::args().collect::<Vec<_>>()).is_some()
}

fn announce(snapshot: &protocol::Snapshot) {
    let Some(session) = snapshot.session.as_ref() else { return };
    eprintln!(
        "[nexguard] mesh up: {} as {} on {} ({})",
        session.address, session.name, session.network, session.tun_name
    );
    if session.serving_exit {
        eprintln!("[nexguard] serving as exit node for {}", session.network);
    } else if session.advertising_exit {
        eprintln!("[nexguard] exit node advertised but not active on this platform");
    }
}

#[cfg(unix)]
fn print_status() {
    match control::request(&control::Request::Status) {
        Ok(snapshot) => println!("{}", control::encode(&snapshot).unwrap_or_default()),
        Err(e) => {
            eprintln!("[nexguard] {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn print_status() {
    eprintln!("[nexguard] --status needs the daemon, which this platform does not run");
}

