fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0;
    while pos < data.len() {
        let line_end = match data[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => pos + p,
            None => break,
        };
        let size_hex = std::str::from_utf8(&data[pos..line_end])
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_hex, 16).unwrap_or(0);
        if size == 0 { break; }
        let start = line_end + 2;
        if start + size > data.len() { break; }
        out.extend_from_slice(&data[start..start + size]);
        pos = start + size + 2;
    }
    out
}

/// Reads a complete HTTP/1.1 response, honoring Content-Length and chunked
/// transfer-encoding. Returns as soon as the body is complete instead of
/// blocking on read-to-EOF: the download server replies `Connection:
/// keep-alive` and never closes, so read-to-EOF stalled for the full
/// socket read timeout on every request.
fn read_http_response<R: std::io::Read>(r: R) -> Result<(u16, Vec<u8>), String> {
    read_http_response_with(r, None, None)
}

fn read_http_response_with<R: std::io::Read>(
    mut r: R,
    progress: Option<&dyn Fn(u64, u64)>,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<(u16, Vec<u8>), String> {
    use std::sync::atomic::Ordering;
    let cancelled = || cancel.is_some_and(|c| c.load(Ordering::Relaxed));
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 16384];

    let header_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = r.read(&mut chunk).map_err(|e| format!("read: {}", e))?;
        if n == 0 { return Err("connection closed before headers".into()); }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 65536 { return Err("response headers too large".into()); }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]);
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("malformed status line")?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        if line.is_empty() { break; }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().ok();
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }

    let mut body = buf[header_end..].to_vec();

    if chunked {
        while !body.ends_with(b"0\r\n\r\n") {
            if cancelled() { return Err("cancelled".into()); }
            let n = r.read(&mut chunk).map_err(|e| format!("read: {}", e))?;
            if n == 0 { break; }
            body.extend_from_slice(&chunk[..n]);
            if let Some(p) = progress { p(body.len() as u64, 0); }
        }
        body = dechunk(&body);
    } else if let Some(cl) = content_length {
        if let Some(p) = progress { p(body.len().min(cl) as u64, cl as u64); }
        while body.len() < cl {
            if cancelled() { return Err("cancelled".into()); }
            let n = r.read(&mut chunk).map_err(|e| format!("read: {}", e))?;
            if n == 0 { break; }
            body.extend_from_slice(&chunk[..n]);
            if let Some(p) = progress { p(body.len().min(cl) as u64, cl as u64); }
        }
        body.truncate(cl);
    } else {
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
    }

    Ok((status, body))
}

pub(crate) const DEFAULT_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const TLS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const HTTPS_PORT: u16 = 443;
pub(crate) const DEFAULT_API_HOST: &str = "api.nexguard.sh";
const API_HOST_ENV: &str = "NEXGUARD_API_HOST";

pub(crate) struct TlsRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub body: Option<&'a str>,
    pub auth: Option<&'a str>,
    pub read_timeout: std::time::Duration,
}

pub(crate) fn user_agent() -> String {
    format!("NexGuard-Client/{}", env!("CARGO_PKG_VERSION"))
}

pub(crate) fn http_tls_request(host: &str, req: TlsRequest) -> Result<(u16, String), String> {
    use std::io::Write;
    ensure_crypto_provider();

    let (sni_host, port) = split_host_port(host);
    let addr = {
        use std::net::ToSocketAddrs;
        format!("{}:{}", sni_host, port)
            .to_socket_addrs()
            .map_err(|e| format!("resolve {}: {}", host, e))?
            .next()
            .ok_or_else(|| format!("resolve {}: no address", host))?
    };
    let mut tcp = std::net::TcpStream::connect_timeout(&addr, TLS_CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {}: {}", host, e))?;
    tcp.set_read_timeout(Some(req.read_timeout)).ok();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let server_name: rustls::pki_types::ServerName = sni_host
        .to_string()
        .try_into()
        .map_err(|_| format!("invalid host {}", host))?;
    let mut conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("tls {}: {}", host, e))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let auth_header = req
        .auth
        .map(|t| format!("Authorization: Bearer {}\r\n", t))
        .unwrap_or_default();
    let body_headers = req
        .body
        .map(|b| format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len()))
        .unwrap_or_default();
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n{}{}Connection: close\r\nUser-Agent: {}\r\n\r\n{}",
        req.method,
        req.path,
        host,
        auth_header,
        body_headers,
        user_agent(),
        req.body.unwrap_or_default()
    );
    tls.write_all(request.as_bytes()).map_err(|e| format!("send: {}", e))?;
    let (status, body) = read_http_response(&mut tls).map_err(|e| format!("read: {}", e))?;
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn http_get_tls_status(host: &str, path: &str) -> Result<(u16, String), String> {
    http_tls_request(
        host,
        TlsRequest {
            method: "GET",
            path,
            body: None,
            auth: None,
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )
}

fn http_get_tls(host: &str, path: &str) -> Option<String> {
    let (status, body) = http_get_tls_status(host, path).ok()?;
    if status != 200 {
        return None;
    }
    Some(body)
}

#[derive(Clone, Default)]
pub struct GeoInfo {
    pub ip: String,
    pub country: String,
    pub city: String,
    pub region: String,
    pub isp: String,
}

pub fn fetch_geo_self() -> Result<GeoInfo, String> {
    let (status, body) = http_get_tls_status(&api_host(), GEO_SELF_PATH)?;
    if status != 200 {
        return Err(format!("geo: HTTP {} — {}", status, body));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("parse geo: {} — {}", e, body))?;
    Ok(GeoInfo {
        ip: v.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        country: v.get("country").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        city: v.get("city").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        region: v.get("region").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        isp: v.get("isp").or_else(|| v.get("org")).and_then(|x| x.as_str()).unwrap_or("").to_string(),
    })
}

const GEO_SELF_PATH: &str = "/api/geo/self";

const VERSION_URL_HOST: &str = "nexguard.sh";
const VERSION_URL_PATH: &str = "/version.json";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct UpdateInfo {
    pub version: String,
    pub download_url: String,
    pub has_update: bool,
    pub force_update: bool,
}

pub fn check_update() -> Option<UpdateInfo> {
    let body = http_get_tls(VERSION_URL_HOST, VERSION_URL_PATH)?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let latest = v.get("client")?.get("version")?.as_str()?;
    let min_version = v.get("client")?.get("min_version").and_then(|v| v.as_str()).unwrap_or("0.0.0");

    let has_update = version_newer(latest, CURRENT_VERSION);
    let force_update = version_newer(min_version, CURRENT_VERSION);
    let platform = detect_platform();
    let url = v.get("client")?
        .get("platforms")?
        .get(&platform)?
        .get("url")?
        .as_str()?
        .to_string();

    Some(UpdateInfo {
        version: latest.to_string(),
        download_url: url,
        has_update,
        force_update,
    })
}

const RELEASE_PUBKEY_HEX: &str = "a9cd9912c215b85684bb1ddbbc5dd6fb3c5e9a232b7097dbc00b37eeb0a73eae";

fn verify_signature(binary: &[u8], signature: &[u8]) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk_bytes = hex::decode(RELEASE_PUBKEY_HEX).map_err(|_| "bad pubkey hex")?;
    let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| "pubkey not 32 bytes")?;
    let pk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| "bad pubkey")?;
    if signature.len() != 64 {
        return Err(format!("bad signature length: {}", signature.len()));
    }
    let sig_arr: [u8; 64] = signature.try_into().map_err(|_| "sig not 64 bytes")?;
    let sig = Signature::from_bytes(&sig_arr);
    pk.verify(binary, &sig).map_err(|e| format!("signature verification failed: {}", e))
}

const UPDATE_BINARY_FILE: &str = "update.bin";
const UPDATE_SIGNATURE_FILE: &str = "update.sig";

pub struct UpdateFiles {
    pub binary: std::path::PathBuf,
    pub signature: std::path::PathBuf,
}

fn decode_signature(raw: Vec<u8>) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(&raw).unwrap_or("").trim();
    if text.len() == 128 {
        hex::decode(text).map_err(|e| format!("bad signature hex: {}", e))
    } else {
        Ok(raw)
    }
}

/// Downloads a release and its signature, verifies them, and leaves both on
/// disk for whoever is allowed to replace the running binary.
pub fn fetch_update(
    url: &str,
    progress: &dyn Fn(u64, u64),
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<UpdateFiles, String> {
    let (host, path) = parse_url(url)?;
    let body = download_tls(&host, &path, Some(progress), Some(cancel))?;
    if body.len() < 1000 || body.starts_with(b"<html") || body.starts_with(b"<!DOCTYPE") {
        return Err("download returned HTML, not a binary".into());
    }
    let sig_path = format!("{}.sig", path);
    let signature = download_tls(&host, &sig_path, None, None)
        .map_err(|e| format!("missing signature {}: {}", sig_path, e))
        .and_then(decode_signature)?;
    verify_signature(&body, &signature)?;
    let dir = crate::dirs_next().ok_or("no config dir")?;
    let files = UpdateFiles {
        binary: dir.join(UPDATE_BINARY_FILE),
        signature: dir.join(UPDATE_SIGNATURE_FILE),
    };
    std::fs::write(&files.binary, &body).map_err(|e| format!("write update: {}", e))?;
    std::fs::write(&files.signature, &signature).map_err(|e| format!("write signature: {}", e))?;
    Ok(files)
}

/// Verifies again before touching anything: the request may come from a less
/// privileged process, and the signature is what makes the swap safe.
pub fn apply_update(binary: &std::path::Path, signature: &std::path::Path) -> Result<(), String> {
    let body = std::fs::read(binary).map_err(|e| format!("read update: {}", e))?;
    let signature = std::fs::read(signature)
        .map_err(|e| format!("read signature: {}", e))
        .and_then(decode_signature)?;
    verify_signature(&body, &signature)?;
    let exe = std::env::current_exe().map_err(|e| format!("current exe: {}", e))?;
    let tmp = exe.with_extension("update");
    std::fs::write(&tmp, &body).map_err(|e| format!("write tmp: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&tmp, &exe).map_err(|e| format!("replace: {}", e))?;
    let _ = std::fs::remove_file(binary);
    Ok(())
}

fn download_tls(
    host: &str,
    path: &str,
    progress: Option<&dyn Fn(u64, u64)>,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Vec<u8>, String> {
    use std::io::Write;
    ensure_crypto_provider();
    let addr = {
        use std::net::ToSocketAddrs;
        format!("{}:443", host).to_socket_addrs()
            .map_err(|e| format!("resolve: {}", e))?
            .next().ok_or("no address")?
    };
    let mut tcp = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(30))
        .map_err(|e| format!("connect: {}", e))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(60))).ok();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let server_name: rustls::pki_types::ServerName = host.to_string().try_into()
        .map_err(|_| "invalid hostname")?;
    let mut conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("tls: {}", e))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: nexguard-updater\r\n\r\n",
        path, host
    );
    tls.write_all(req.as_bytes()).map_err(|e| format!("write: {}", e))?;
    let (status, body) = read_http_response_with(&mut tls, progress, cancel)?;
    if status != 200 {
        return Err(format!("HTTP {}", status));
    }
    Ok(body)
}

const MACOS_BUNDLE_SUFFIX: &str = ".app/Contents/MacOS/";

/// A bundled app must come back through LaunchServices, or the Dock ends up
/// pointing at a process that no longer exists.
#[cfg(target_os = "macos")]
fn relaunch_bundle(exe: &std::path::Path) -> bool {
    let path = exe.to_string_lossy();
    let Some(idx) = path.find(MACOS_BUNDLE_SUFFIX) else { return false };
    let bundle = &path[..idx + ".app".len()];
    std::process::Command::new("open").args(["-n", bundle]).spawn().is_ok()
}

#[cfg(not(target_os = "macos"))]
fn relaunch_bundle(_exe: &std::path::Path) -> bool {
    false
}

pub fn restart_self() -> ! {
    let exe = std::env::current_exe().expect("current exe");
    let args: Vec<String> = std::env::args().collect();
    eprintln!("[nexguard] restarting...");
    if relaunch_bundle(&exe) {
        std::process::exit(0);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&exe).args(&args[1..]).exec();
        eprintln!("[nexguard] restart failed: {}", err);
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        let _ = std::process::Command::new(&exe).args(&args[1..]).spawn();
        std::process::exit(0);
    }
}

fn version_newer(latest: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> {
        s.split('.').filter_map(|p| p.parse().ok()).collect()
    };
    let l = parse(latest);
    let c = parse(current);
    for i in 0..l.len().max(c.len()) {
        let a = l.get(i).copied().unwrap_or(0);
        let b = c.get(i).copied().unwrap_or(0);
        if a > b { return true; }
        if a < b { return false; }
    }
    false
}

fn detect_platform() -> String {
    let os = if cfg!(target_os = "macos") { "macos" }
        else if cfg!(target_os = "windows") { "windows" }
        else { "linux" };
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
    format!("{}-{}", os, arch)
}

fn parse_url(url: &str) -> Result<(String, String), String> {
    let stripped = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let (host, path) = stripped.split_once('/')
        .ok_or("invalid url")?;
    Ok((host.to_string(), format!("/{}", path)))
}

const LOGIN_PURPOSE_ACCOUNT: &str = "account";
const AUTH_DEVICE_PATH: &str = "/api/auth/device";
const AUTH_CHECK_PATH: &str = "/api/auth/device/check?token=";
const STATUS_CONFIRMED: &str = "confirmed";

#[derive(serde::Deserialize, Clone)]
#[allow(dead_code)]
pub struct DeviceLoginResp {
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub login_url: String,
    #[serde(default)]
    pub expires: u64,
}

#[derive(serde::Deserialize, Clone)]
pub struct DeviceCheckResp {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub token: String,
}

const ACCOUNT_TOKEN_FILE: &str = "account.token";

pub fn save_account_token(token: &str) {
    let path = match crate::dirs_next() {
        Some(dir) => dir.join(ACCOUNT_TOKEN_FILE),
        None => return,
    };
    if std::fs::write(&path, token).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

pub fn account_email() -> Option<String> {
    let token = load_account_token()?;
    let payload = token.split('.').nth(1)?;
    use base64::Engine;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims["email"]
        .as_str()
        .filter(|e| !e.is_empty())
        .map(|e| e.to_string())
}

pub fn clear_account_token() {
    if let Some(dir) = crate::dirs_next() {
        let _ = std::fs::remove_file(dir.join(ACCOUNT_TOKEN_FILE));
    }
}

pub fn load_account_token() -> Option<String> {
    let path = crate::dirs_next()?.join(ACCOUNT_TOKEN_FILE);
    let token = std::fs::read_to_string(path).ok()?.trim().to_string();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}


pub(crate) fn api_host() -> String {
    if let Ok(host) = std::env::var(API_HOST_ENV) {
        let host = host.trim();
        if !host.is_empty() {
            return host.to_string();
        }
    }
    let configured = crate::profiles::load_settings().api_host;
    let configured = configured.trim();
    if configured.is_empty() {
        DEFAULT_API_HOST.to_string()
    } else {
        configured.to_string()
    }
}

fn split_host_port(host: &str) -> (&str, u16) {
    match host.rsplit_once(':') {
        Some((name, port)) if !name.is_empty() && !name.contains(':') => {
            match port.parse::<u16>() {
                Ok(p) => (name, p),
                Err(_) => (host, HTTPS_PORT),
            }
        }
        _ => (host, HTTPS_PORT),
    }
}

fn http_post_tls_json(host: &str, path: &str, body: &str, auth_token: Option<&str>) -> Result<(u16, String), String> {
    http_tls_request(
        host,
        TlsRequest {
            method: "POST",
            path,
            body: Some(body),
            auth: auth_token,
            read_timeout: DEFAULT_READ_TIMEOUT,
        },
    )
}

pub fn request_account_login() -> Result<DeviceLoginResp, String> {
    let host = api_host();
    let body = serde_json::json!({ "purpose": LOGIN_PURPOSE_ACCOUNT }).to_string();
    let (status, body) = http_post_tls_json(&host, AUTH_DEVICE_PATH, &body, None)?;
    if status != 200 {
        return Err(format!("device login failed: HTTP {} — {}", status, body));
    }
    serde_json::from_str(&body).map_err(|e| format!("parse device login: {} — {}", e, body))
}

pub fn poll_account_login(pairing_token: &str) -> Result<Option<String>, String> {
    let host = api_host();
    let path = format!("{}{}", AUTH_CHECK_PATH, pairing_token);
    let (status, body) = http_get_tls_status(&host, &path)?;
    if status != 200 {
        return Err(format!("sign-in check failed: HTTP {} — {}", status, body));
    }
    let resp: DeviceCheckResp = serde_json::from_str(&body)
        .map_err(|e| format!("parse sign-in check: {} — {}", e, body))?;
    if resp.status != STATUS_CONFIRMED {
        return Ok(None);
    }
    if resp.token.is_empty() {
        return Err("sign-in returned no token".to_string());
    }
    save_account_token(&resp.token);
    Ok(Some(resp.token))
}
