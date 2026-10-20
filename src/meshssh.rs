//! SSH served by the mesh itself, the way Tailscale SSH works: a device that
//! opts in with `--ssh` answers port 22 on its mesh address, with no sshd and
//! no keys. Who is calling is settled by the tunnel, which only delivers a mesh
//! source address from the device that owns it; any device in the project may
//! open a shell as any local account except root.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Config, Handle, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::meshtypes::MeshPeerView;

const SSH_PORT: u16 = 22;
const HOST_KEY_FILE: &str = "ssh_host_ed25519.key";
const SEED_LEN: usize = 32;
const SHUTDOWN_POLL: Duration = Duration::from_millis(500);
const BIND_RETRIES: u32 = 4;
const AUTH_REJECTION_TIME: Duration = Duration::from_secs(1);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const READ_CHUNK: usize = 32 * 1024;
const STDERR_STREAM: u32 = 1;
const EXIT_FAILURE: u32 = 255;
const SIGNAL_EXIT_BASE: u32 = 128;
const ROOT_UID: libc::uid_t = 0;
const DEFAULT_SHELL: &str = "/bin/sh";
const SFTP_SUBSYSTEM: &str = "sftp";
const PASSED_ENV: [&str; 2] = ["LANG", "TERM"];
const PASSED_ENV_PREFIX: &str = "LC_";

#[cfg(target_os = "linux")]
const SEARCH_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
#[cfg(target_os = "macos")]
const SEARCH_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

#[cfg(target_os = "linux")]
const SFTP_SERVERS: [&str; 3] = [
    "/usr/lib/ssh/sftp-server",
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
];
#[cfg(target_os = "macos")]
const SFTP_SERVERS: [&str; 1] = ["/usr/libexec/sftp-server"];

/// Starts serving SSH on `address`, bound to the tunnel so nothing that
/// arrives on another interface reaches it, until `shutdown` is set.
pub fn start(
    address: Ipv4Addr,
    tun_name: &str,
    peers: Arc<Mutex<Vec<MeshPeerView>>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    if unsafe { libc::geteuid() } != ROOT_UID {
        return Err("ssh: needs root to open shells as other accounts".into());
    }
    let listener = bind_port(address)?;
    bind_to_interface(listener.as_raw_fd(), tun_name)?;
    serve_listener(listener, peers, shutdown)
}

/// A reconnect starts the next server while the previous one is still
/// noticing its shutdown, so the port gets a moment to come free.
fn bind_port(address: Ipv4Addr) -> Result<StdListener, String> {
    let mut attempt = 0;
    loop {
        match StdListener::bind((address, SSH_PORT)) {
            Ok(listener) => return Ok(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && attempt < BIND_RETRIES => {
                attempt += 1;
                std::thread::sleep(SHUTDOWN_POLL);
            }
            Err(e) => return Err(format!("ssh: port {} on {}: {}", SSH_PORT, address, e)),
        }
    }
}

/// Serves SSH on a socket already bound; `start` is the one caller that
/// matters, the split only keeps the privileged bind apart from the serving.
pub fn serve_listener(
    listener: StdListener,
    peers: Arc<Mutex<Vec<MeshPeerView>>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    listener.set_nonblocking(true).map_err(|e| format!("ssh: {}", e))?;
    let config = server_config(load_or_create_host_key()?);

    std::thread::Builder::new()
        .name("mesh-ssh".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(e) => {
                    eprintln!("[nexguard] ssh: {}", e);
                    return;
                }
            };
            runtime.block_on(serve(listener, config, peers, shutdown));
        })
        .map_err(|e| format!("ssh: {}", e))?;
    Ok(())
}

async fn serve(
    listener: StdListener,
    config: Config,
    peers: Arc<Mutex<Vec<MeshPeerView>>>,
    shutdown: Arc<AtomicBool>,
) {
    let listener = match tokio::net::TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("[nexguard] ssh: {}", e);
            return;
        }
    };
    let mut server = MeshSsh { peers };
    let running = server.run_on_socket(Arc::new(config), &listener);
    let handle = running.handle();
    tokio::spawn(async move {
        while !shutdown.load(Ordering::Relaxed) {
            tokio::time::sleep(SHUTDOWN_POLL).await;
        }
        handle.shutdown("mesh disconnected".into());
    });
    if let Err(e) = running.await {
        eprintln!("[nexguard] ssh: {}", e);
    }
}

fn server_config(host_key: PrivateKey) -> Config {
    Config {
        methods: MethodSet::from(&[MethodKind::None, MethodKind::PublicKey][..]),
        auth_rejection_time: AUTH_REJECTION_TIME,
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![host_key],
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        inactivity_timeout: None,
        ..Default::default()
    }
}

#[cfg(target_os = "linux")]
fn bind_to_interface(fd: RawFd, tun_name: &str) -> Result<(), String> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            tun_name.as_ptr() as *const libc::c_void,
            tun_name.len() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("ssh: bind to {}: {}", tun_name, std::io::Error::last_os_error()))
    }
}

#[cfg(target_os = "macos")]
fn bind_to_interface(fd: RawFd, tun_name: &str) -> Result<(), String> {
    let name = CString::new(tun_name).map_err(|e| format!("ssh: {}", e))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(format!("ssh: no interface {}", tun_name));
    }
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            &index as *const libc::c_uint as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("ssh: bind to {}: {}", tun_name, std::io::Error::last_os_error()))
    }
}

/// The host key lives beside the device key, readable by root alone, so the
/// fingerprint a client pins stays the same across restarts.
fn load_or_create_host_key() -> Result<PrivateKey, String> {
    let path = host_key_path()?;
    let seed = match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == SEED_LEN => bytes,
        _ => {
            let mut fresh = vec![0u8; SEED_LEN];
            crate::rng::fill(&mut fresh);
            write_private(&path, &fresh)?;
            fresh
        }
    };
    let mut array = [0u8; SEED_LEN];
    array.copy_from_slice(&seed);
    Ok(PrivateKey::from(Ed25519Keypair::from_seed(&array)))
}

fn host_key_path() -> Result<PathBuf, String> {
    crate::keys::dirs_next()
        .map(|dir| dir.join(HOST_KEY_FILE))
        .ok_or_else(|| "ssh: no config directory for the host key".into())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("ssh: {}", e))?;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|e| format!("ssh: host key {}: {}", path.display(), e))
}

/// Any device in the network may connect; the network is the project.
pub fn caller_of(peers: &[MeshPeerView], from: Option<SocketAddr>) -> Option<MeshPeerView> {
    let IpAddr::V4(ip) = from?.ip() else {
        return None;
    };
    let ip = ip.to_string();
    peers.iter().find(|p| p.ip == ip).cloned()
}

#[derive(Clone)]
pub struct Account {
    pub name: String,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub home: String,
    pub shell: String,
}

/// A local account a caller may become: one that exists and is not root.
pub fn login_account(name: &str) -> Option<Account> {
    lookup_account(name).filter(|account| account.uid != ROOT_UID)
}

fn lookup_account(name: &str) -> Option<Account> {
    let cname = CString::new(name).ok()?;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(cname.as_ptr(), &mut entry, buf.as_mut_ptr(), buf.len(), &mut found)
    };
    if rc != 0 || found.is_null() {
        return None;
    }
    let text = |ptr: *const libc::c_char| {
        if ptr.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
        }
    };
    let shell = text(entry.pw_shell);
    Some(Account {
        name: text(entry.pw_name),
        uid: entry.pw_uid,
        gid: entry.pw_gid,
        home: text(entry.pw_dir),
        shell: if shell.is_empty() { DEFAULT_SHELL.to_string() } else { shell },
    })
}

pub fn passes_env(name: &str) -> bool {
    PASSED_ENV.contains(&name) || name.starts_with(PASSED_ENV_PREFIX)
}

struct MeshSsh {
    peers: Arc<Mutex<Vec<MeshPeerView>>>,
}

impl Server for MeshSsh {
    type Handler = Connection;

    fn new_client(&mut self, from: Option<SocketAddr>) -> Connection {
        let caller = self.peers.lock().ok().and_then(|peers| caller_of(&peers, from));
        Connection { caller, account: None, channels: HashMap::new() }
    }
}

#[derive(Default)]
struct PtyRequest {
    term: String,
    cols: u32,
    rows: u32,
}

#[derive(Default)]
struct ChannelState {
    pty: Option<PtyRequest>,
    env: Vec<(String, String)>,
    input: Option<mpsc::UnboundedSender<Vec<u8>>>,
    master: Option<Arc<OwnedFd>>,
}

struct Connection {
    caller: Option<MeshPeerView>,
    account: Option<Account>,
    channels: HashMap<ChannelId, ChannelState>,
}

impl Connection {
    fn admit(&mut self, user: &str) -> Auth {
        if self.caller.is_none() {
            return Auth::reject();
        }
        match login_account(user) {
            Some(account) => {
                self.account = Some(account);
                Auth::Accept
            }
            None => Auth::reject(),
        }
    }

    fn launch(&mut self, channel: ChannelId, program: Program, session: &mut Session) -> Result<(), russh::Error> {
        let (Some(account), Some(state)) = (self.account.clone(), self.channels.get_mut(&channel)) else {
            return session.channel_failure(channel);
        };
        let handle = session.handle();
        let started = match state.pty.as_ref() {
            Some(pty) => spawn_on_pty(&account, &program, pty, &state.env, channel, handle),
            None => spawn_on_pipes(&account, &program, &state.env, channel, handle),
        };
        match started {
            Ok((input, master)) => {
                state.input = Some(input);
                state.master = master;
                session.channel_success(channel)
            }
            Err(e) => {
                eprintln!("[nexguard] ssh: {}", e);
                session.channel_failure(channel)
            }
        }
    }
}

impl Handler for Connection {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        Ok(self.admit(user))
    }

    async fn auth_publickey_offered(&mut self, user: &str, _: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(self.admit(user))
    }

    async fn auth_publickey(&mut self, user: &str, _: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(self.admit(user))
    }

    async fn auth_succeeded(&mut self, _: &mut Session) -> Result<(), Self::Error> {
        if let (Some(caller), Some(account)) = (self.caller.as_ref(), self.account.as_ref()) {
            eprintln!("[nexguard] ssh: {} from {} ({})", account.name, caller.name, caller.ip);
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), ChannelState::default());
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.channels.get_mut(&channel) {
            Some(state) => {
                state.pty = Some(PtyRequest { term: term.to_string(), cols, rows });
                session.channel_success(channel)
            }
            None => session.channel_failure(channel),
        }
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get_mut(&channel).filter(|_| passes_env(name)) {
            state.env.push((name.to_string(), value.to_string()));
        }
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.launch(channel, Program::LoginShell, session)
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.launch(channel, Program::Command(command), session)
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        match sftp_server().filter(|_| name == SFTP_SUBSYSTEM) {
            Some(path) => self.launch(channel, Program::Subsystem(path), session),
            None => session.channel_failure(channel),
        }
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(master) = self.channels.get(&channel).and_then(|s| s.master.as_ref()) {
            resize(master.as_raw_fd(), cols, rows);
        }
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], _: &mut Session) -> Result<(), Self::Error> {
        if let Some(input) = self.channels.get(&channel).and_then(|s| s.input.as_ref()) {
            let _ = input.send(data.to_vec());
        }
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get_mut(&channel).filter(|s| s.pty.is_none()) {
            state.input = None;
        }
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }
}

enum Program {
    LoginShell,
    Command(String),
    Subsystem(PathBuf),
}

fn sftp_server() -> Option<PathBuf> {
    SFTP_SERVERS.iter().map(PathBuf::from).find(|path| path.exists())
}

fn command_for(account: &Account, program: &Program, env: &[(String, String)], term: Option<&str>) -> Command {
    let mut command = match program {
        Program::LoginShell => {
            let mut command = Command::new(&account.shell);
            command.arg0(login_name(&account.shell));
            command
        }
        Program::Command(line) => {
            let mut command = Command::new(&account.shell);
            command.arg("-c").arg(line);
            command
        }
        Program::Subsystem(path) => Command::new(path),
    };
    command
        .env_clear()
        .env("HOME", &account.home)
        .env("USER", &account.name)
        .env("LOGNAME", &account.name)
        .env("SHELL", &account.shell)
        .env("PATH", SEARCH_PATH)
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .current_dir(&account.home)
        .kill_on_drop(true);
    if let Some(term) = term {
        command.env("TERM", term);
    }
    command
}

/// `-bash` rather than `bash`: the leading dash is how a shell learns it is a
/// login shell and reads the profile.
pub fn login_name(shell: &str) -> String {
    let base = Path::new(shell).file_name().and_then(|n| n.to_str()).unwrap_or(shell);
    format!("-{}", base)
}

/// Runs in the child between fork and exec: a fresh session, the terminal as
/// its controlling one when there is a terminal, then the account's groups and
/// ids, dropped in that order so root is gone before anything of theirs runs.
fn become_account(command: &mut Command, account: &Account, controlling_tty: bool) -> Result<(), String> {
    let name = CString::new(account.name.clone()).map_err(|e| format!("ssh: {}", e))?;
    let (uid, gid) = (account.uid, account.gid);
    let already = unsafe { libc::geteuid() } == uid;
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if controlling_tty && libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if !already
                && (libc::initgroups(name.as_ptr(), gid as _) < 0
                    || libc::setgid(gid) < 0
                    || libc::setuid(uid) < 0)
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

type Started = (mpsc::UnboundedSender<Vec<u8>>, Option<Arc<OwnedFd>>);

fn spawn_on_pipes(
    account: &Account,
    program: &Program,
    env: &[(String, String)],
    channel: ChannelId,
    handle: Handle,
) -> Result<Started, String> {
    let mut command = command_for(account, program, env, None);
    become_account(&mut command, account, false)?;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn for {}: {}", account.name, e))?;
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    if let Some(mut stdin) = child.stdin.take() {
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                if stdin.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    tokio::spawn(async move {
        let out = pump(stdout, handle.clone(), channel, None);
        let err = pump(stderr, handle.clone(), channel, Some(STDERR_STREAM));
        tokio::join!(out, err);
        let status = child.wait().await.map(exit_code).unwrap_or(EXIT_FAILURE);
        finish(&handle, channel, status).await;
    });
    Ok((tx, None))
}

fn spawn_on_pty(
    account: &Account,
    program: &Program,
    pty: &PtyRequest,
    env: &[(String, String)],
    channel: ChannelId,
    handle: Handle,
) -> Result<Started, String> {
    let (master, slave) = open_pty()?;
    resize(master.as_raw_fd(), pty.cols, pty.rows);
    let stdio = |fd: &OwnedFd| fd.try_clone().map(Stdio::from).map_err(|e| format!("pty: {}", e));
    let mut command = command_for(account, program, env, Some(&pty.term));
    become_account(&mut command, account, true)?;
    command.stdin(stdio(&slave)?).stdout(stdio(&slave)?).stderr(stdio(&slave)?);
    let mut child = command.spawn().map_err(|e| format!("spawn for {}: {}", account.name, e))?;
    drop(slave);

    let master = Arc::new(master);
    let reader = tokio::fs::File::from_std(std::fs::File::from(master.try_clone().map_err(|e| format!("pty: {}", e))?));
    let mut writer = tokio::fs::File::from_std(std::fs::File::from(master.try_clone().map_err(|e| format!("pty: {}", e))?));
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(chunk) = rx.recv().await {
            if writer.write_all(&chunk).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        pump(Some(reader), handle.clone(), channel, None).await;
        let status = child.wait().await.map(exit_code).unwrap_or(EXIT_FAILURE);
        finish(&handle, channel, status).await;
    });
    Ok((tx, Some(master)))
}

async fn pump<R: AsyncRead + Unpin>(source: Option<R>, handle: Handle, channel: ChannelId, stream: Option<u32>) {
    let Some(mut source) = source else {
        return;
    };
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        match source.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let chunk = buf[..n].to_vec();
                let sent = match stream {
                    Some(ext) => handle.extended_data(channel, ext, chunk).await.is_ok(),
                    None => handle.data(channel, chunk).await.is_ok(),
                };
                if !sent {
                    break;
                }
            }
        }
    }
}

async fn finish(handle: &Handle, channel: ChannelId, status: u32) {
    let _ = handle.exit_status_request(channel, status).await;
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
}

pub fn exit_code(status: std::process::ExitStatus) -> u32 {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => code as u32,
        (None, Some(signal)) => SIGNAL_EXIT_BASE + signal as u32,
        (None, None) => EXIT_FAILURE,
    }
}

fn open_pty() -> Result<(OwnedFd, OwnedFd), String> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    let rc = unsafe {
        libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
    };
    if rc < 0 {
        return Err(format!("openpty: {}", std::io::Error::last_os_error()));
    }
    unsafe {
        libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC);
        Ok((OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)))
    }
}

fn resize(master: RawFd, cols: u32, rows: u32) {
    let size = libc::winsize {
        ws_row: rows.min(u16::MAX as u32) as u16,
        ws_col: cols.min(u16::MAX as u32) as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(master, libc::TIOCSWINSZ as _, &size);
    }
}
