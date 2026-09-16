use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::engine::Engine;
pub use crate::protocol::{decode, encode, Request, Response, Snapshot};

#[cfg(target_os = "macos")]
const SOCKET_PATH: &str = "/var/run/nexguard.sock";
#[cfg(target_os = "linux")]
const SOCKET_PATH: &str = "/run/nexguard.sock";
pub const OPERATOR_UID_ENV: &str = "NEXGUARD_OPERATOR_UID";
#[cfg(target_os = "macos")]
const CONSOLE_DEVICE: &str = "/dev/console";

const QUICK_TIMEOUT: Duration = Duration::from_secs(5);

/// Every request, whatever transport it arrived over, ends up here.
pub fn dispatch(engine: &Engine, request: Request) -> Response {
    let result = match request {
        Request::Status => Ok(engine.snapshot()),
        Request::Connect { config } => engine.connect(config),
        Request::Disconnect => Ok(engine.disconnect()),
        Request::Leave => engine.leave(),
        Request::ClearIdentity => Ok(engine.clear_identity()),
        Request::AdvertiseExit { enabled } => engine.advertise_exit(enabled),
        Request::ApplyUpdate { binary, signature } => {
            crate::api::apply_update(&PathBuf::from(binary), &PathBuf::from(signature)).map(|()| engine.snapshot())
        }
        Request::Restart => {
            engine.disconnect();
            RESTART_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(engine.snapshot())
        }
    };
    Response::from(result)
}

pub static RESTART_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub const SOCKET_ENV: &str = "NEXGUARD_SOCKET";

#[cfg(unix)]
pub fn socket_path() -> PathBuf {
    std::env::var(SOCKET_ENV)
        .ok()
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(SOCKET_PATH))
}

/// Binds the control socket and answers on it forever. Callers that must not
/// block (the headless CLI, which also has a tunnel to run) spawn this.
#[cfg(unix)]
pub fn serve(engine: Arc<Engine>) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| format!("bind {}: {}", path.display(), e))?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
    for stream in listener.incoming().flatten() {
        let Some(uid) = peer_uid(&stream) else { continue };
        if !operator_allowed(uid) {
            continue;
        }
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || answer(engine, stream));
    }
    Ok(())
}

#[cfg(unix)]
fn answer(engine: Arc<Engine>, stream: std::os::unix::net::UnixStream) {
    let _ = stream.set_read_timeout(Some(QUICK_TIMEOUT));
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }
    let response = match decode::<Request>(&line) {
        Ok(request) => dispatch(&engine, request),
        Err(error) => Response { ok: false, error, snapshot: None },
    };
    let mut writer = &stream;
    if let Ok(encoded) = encode(&response) {
        let _ = writer.write_all(encoded.as_bytes());
        let _ = writer.write_all(b"\n");
    }
}

/// Root, the user who installed the daemon, and on a Mac whoever is at the
/// console may drive the tunnel; nobody else on the machine can.
#[cfg(unix)]
fn operator_allowed(uid: u32) -> bool {
    if uid == 0 {
        return true;
    }
    if std::env::var(OPERATOR_UID_ENV).ok().and_then(|v| v.parse::<u32>().ok()) == Some(uid) {
        return true;
    }
    console_uid() == Some(uid)
}

#[cfg(target_os = "macos")]
pub fn console_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(CONSOLE_DEVICE).ok().map(|m| m.uid()).filter(|uid| *uid != 0)
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn console_uid() -> Option<u32> {
    None
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

#[cfg(unix)]
pub fn request(request: &Request) -> Result<Snapshot, String> {
    use std::os::unix::net::UnixStream;
    let path = socket_path();
    let mut stream = UnixStream::connect(&path).map_err(|e| format!("{}: {}", DAEMON_UNREACHABLE, e))?;
    let _ = stream.set_read_timeout(Some(request.timeout()));
    let _ = stream.set_write_timeout(Some(QUICK_TIMEOUT));
    stream.write_all(encode(request)?.as_bytes()).map_err(|e| format!("send: {}", e))?;
    stream.write_all(b"\n").map_err(|e| format!("send: {}", e))?;
    let mut line = String::new();
    BufReader::new(&stream)
        .read_line(&mut line)
        .map_err(|e| format!("reply: {}", e))?;
    decode::<Response>(&line)?.into_result()
}

pub const DAEMON_UNREACHABLE: &str = "daemon unreachable";
