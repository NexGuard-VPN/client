use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[allow(dead_code)]
pub struct JoinResponse {
    pub address: String,
    #[serde(default)]
    pub address_v6: Option<String>,
    pub server_public_key: String,
    #[serde(default)]
    pub peers: Vec<serde_json::Value>,
    #[serde(default)]
    pub vpn_network: Option<String>,
    #[serde(default)]
    pub vpn_network_v6: Option<String>,
    #[serde(default)]
    pub exit_node: Option<bool>,
    #[serde(default)]
    pub server_endpoint: Option<String>,
    #[serde(default)]
    pub mesh: Option<bool>,
    #[serde(default)]
    pub mesh_peers: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub dns: Option<serde_json::Value>,
}

pub fn parse_dns_servers(value: Option<&serde_json::Value>) -> Vec<String> {
    let raw: Vec<String> = match value {
        Some(serde_json::Value::String(s)) => {
            s.split(DNS_LIST_SEPARATOR).map(|p| p.trim().to_string()).collect()
        }
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .collect(),
        _ => Vec::new(),
    };
    let mut servers: Vec<String> = Vec::new();
    for entry in raw {
        if entry.parse::<std::net::IpAddr>().is_ok() && !servers.contains(&entry) {
            servers.push(entry);
        }
    }
    servers
}

pub struct MeshPeerInfo {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub name: String,
}

const USER_AGENT: &str = concat!("nexguard/", env!("CARGO_PKG_VERSION"));
const JSON_CONTENT_TYPE: &str = "application/json";
const HTTPS_PORT: u16 = 443;
const DEVICE_ID_FILE: &str = "device-hwid";
const JOIN_PATH: &str = "/api/v1/join";
const REKEY_PATH: &str = "/api/v1/rekey";
const REKEY_OK_MARKER: &str = "\"rekeyed\"";
const MESH_PEERS_PATH: &str = "/api/v1/mesh/peers";
const CONNECT_INFO_PATH: &str = "/api/vpn/connect-info";
const DEFAULT_JOIN_PATH: &str = "api/vpn/join";
const DEFAULT_API_HOST: &str = "api.nexguard.sh";
const API_HOST_ENV: &str = "NEXGUARD_API_HOST";
const ERROR_FIELDS: [&str; 2] = ["error", "message"];
pub const DNS_LIST_SEPARATOR: char = ',';

struct Transport {
    connect_timeout: Duration,
    read_timeout: Duration,
    max_body: usize,
}

const API_TRANSPORT: Transport = Transport {
    connect_timeout: Duration::from_secs(10),
    read_timeout: Duration::from_secs(10),
    max_body: 1024 * 1024,
};

const DOWNLOAD_TRANSPORT: Transport = Transport {
    connect_timeout: Duration::from_secs(30),
    read_timeout: Duration::from_secs(60),
    max_body: 256 * 1024 * 1024,
};

struct HttpRequest<'a> {
    method: &'a str,
    path: &'a str,
    host: &'a str,
    token: Option<&'a str>,
    body: &'a str,
}

impl<'a> HttpRequest<'a> {
    fn get(host: &'a str, path: &'a str) -> Self {
        Self { method: "GET", path, host, token: None, body: "" }
    }

    fn post_json(host: &'a str, path: &'a str, body: &'a str) -> Self {
        Self { method: "POST", path, host, token: None, body }
    }

    fn bearer(mut self, token: &'a str) -> Self {
        self.token = Some(token);
        self
    }

    fn render(&self) -> String {
        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n",
            sanitize_request_target(self.method),
            sanitize_request_target(self.path),
            sanitize_header_value(self.host),
            USER_AGENT,
        );
        if let Some(token) = self.token {
            req.push_str(&format!("Authorization: Bearer {}\r\n", sanitize_header_value(token)));
        }
        if !self.body.is_empty() {
            req.push_str(&format!(
                "Content-Type: {}\r\nContent-Length: {}\r\n",
                JSON_CONTENT_TYPE,
                self.body.len()
            ));
        }
        req.push_str("\r\n");
        req.push_str(self.body);
        req
    }
}

fn sanitize_header_value(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

fn sanitize_request_target(value: &str) -> String {
    value.chars().filter(|c| !c.is_control() && !c.is_whitespace()).collect()
}

fn https_host_port(host: &str) -> String {
    format!("{}:{}", host, HTTPS_PORT)
}

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    std::sync::Arc::new(
        rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
    )
}

fn send_request(
    host_port: &str,
    request: &HttpRequest,
    transport: &Transport,
) -> Result<(u16, Vec<u8>), String> {
    use std::net::ToSocketAddrs;
    let addr = host_port
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {}", host_port, e))?
        .next()
        .ok_or_else(|| format!("no address for {}", host_port))?;

    let mut tcp = std::net::TcpStream::connect_timeout(&addr, transport.connect_timeout)
        .map_err(|e| format!("connect {}: {}", host_port, e))?;
    tcp.set_read_timeout(Some(transport.read_timeout)).ok();

    let raw = request.render();

    if addr.ip().is_loopback() {
        tcp.write_all(raw.as_bytes()).map_err(|e| format!("write {}: {}", host_port, e))?;
        return read_http_response(&mut tcp, transport.max_body);
    }

    ensure_crypto_provider();
    let host_name = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    let server_name: rustls::pki_types::ServerName =
        host_name.to_string().try_into().map_err(|_| "invalid hostname".to_string())?;
    let mut conn = rustls::ClientConnection::new(tls_config(), server_name)
        .map_err(|e| format!("tls: {}", e))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(raw.as_bytes()).map_err(|e| format!("write {}: {}", host_port, e))?;
    read_http_response(&mut tls, transport.max_body)
}

fn response_error(status: u16, body: &str) -> String {
    let detail = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            ERROR_FIELDS
                .iter()
                .find_map(|k| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string()))
        })
        .unwrap_or_else(|| body.trim().to_string());

    match (status, detail.is_empty()) {
        (401 | 403, true) => "invalid token".to_string(),
        (401 | 403, false) => format!("invalid token: {}", detail),
        (_, true) => format!("HTTP {}", status),
        (_, false) => format!("HTTP {}: {}", status, detail),
    }
}

fn request_body(host_port: &str, request: &HttpRequest) -> Result<String, String> {
    let (status, body) = send_request(host_port, request, &API_TRANSPORT)?;
    let text = String::from_utf8_lossy(&body).into_owned();
    if status != 200 {
        return Err(response_error(status, &text));
    }
    Ok(text)
}

fn https_get_text(host: &str, path: &str) -> Option<String> {
    request_body(&https_host_port(host), &HttpRequest::get(host, path)).ok()
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
fn read_http_response<R: std::io::Read>(mut r: R, max_body: usize) -> Result<(u16, Vec<u8>), String> {
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
        while !body.ends_with(b"0\r\n\r\n") && body.len() < max_body {
            let n = r.read(&mut chunk).map_err(|e| format!("read: {}", e))?;
            if n == 0 { break; }
            body.extend_from_slice(&chunk[..n]);
        }
        body = dechunk(&body);
    } else if let Some(cl) = content_length {
        let want = cl.min(max_body);
        while body.len() < want {
            let n = r.read(&mut chunk).map_err(|e| format!("read: {}", e))?;
            if n == 0 { break; }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(want);
    } else {
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
            if body.len() >= max_body { break; }
        }
    }

    body.truncate(max_body);
    Ok((status, body))
}

pub fn get_mesh_peers(server: &str, control_port: u16, token: &str) -> Vec<MeshPeerInfo> {
    let host = control_host(server, control_port);
    match request_body(&host, &HttpRequest::get(&host, MESH_PEERS_PATH).bearer(token)) {
        Ok(body) => parse_mesh_peers_json(&body),
        Err(e) => {
            eprintln!("[nexguard] mesh peers: {}", e);
            Vec::new()
        }
    }
}

pub fn parse_mesh_peers(values: &[serde_json::Value]) -> Vec<MeshPeerInfo> {
    values.iter().filter_map(|v| {
        let public_key = v.get("public_key")?.as_str()?.to_string();
        let endpoint = v.get("endpoint").and_then(|e| e.as_str()).map(|s| s.to_string());
        let allowed_ips = v.get("allowed_ips")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        Some(MeshPeerInfo { public_key, endpoint, allowed_ips, name })
    }).collect()
}

fn parse_mesh_peers_json(body: &str) -> Vec<MeshPeerInfo> {
    #[derive(serde::Deserialize)]
    struct Resp { peers: Vec<serde_json::Value> }
    match serde_json::from_str::<Resp>(body) {
        Ok(r) => parse_mesh_peers(&r.peers),
        Err(_) => Vec::new(),
    }
}

struct JoinPayload {
    body: String,
    device_id_path: PathBuf,
}

fn build_join_payload(pub_key: &str, name: &str, advertise_routes: &[String]) -> Result<JoinPayload, String> {
    let device_id_path = crate::dirs_next().map(|d| d.join(DEVICE_ID_FILE)).unwrap_or_default();
    let saved_device_id = std::fs::read_to_string(&device_id_path).unwrap_or_default().trim().to_string();
    let mut payload = serde_json::json!({
        "public_key": pub_key,
        "name": name,
        "version": CURRENT_VERSION,
        "fingerprint": crate::fingerprint::collect(),
        "device_id": saved_device_id,
    });
    if !advertise_routes.is_empty() {
        payload["advertise_routes"] = serde_json::json!(advertise_routes);
    }
    let body = serde_json::to_string(&payload).map_err(|e| format!("encode: {}", e))?;
    Ok(JoinPayload { body, device_id_path })
}

fn parse_join_response(body: &str, device_id_path: &Path) -> Result<JoinResponse, String> {
    let join_resp: JoinResponse = serde_json::from_str(body)
        .map_err(|e| format!("join parse error: {} — {}", e, body))?;

    if let Some(ref did) = join_resp.device_id {
        if !did.is_empty() {
            let _ = std::fs::write(device_id_path, did);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(device_id_path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    Ok(join_resp)
}

pub fn try_join_server(
    server: &str,
    control_port: u16,
    token: &str,
    pub_key: &str,
    name: &str,
) -> Result<JoinResponse, String> {
    try_join_server_with_routes(server, control_port, token, pub_key, name, &[])
}

pub fn try_join_server_with_routes(
    server: &str,
    control_port: u16,
    token: &str,
    pub_key: &str,
    name: &str,
    advertise_routes: &[String],
) -> Result<JoinResponse, String> {
    let host = control_host(server, control_port);
    let payload = build_join_payload(pub_key, name, advertise_routes)?;
    let body = request_body(
        &host,
        &HttpRequest::post_json(&host, JOIN_PATH, &payload.body).bearer(token),
    )
    .map_err(|e| format!("join failed: {}", e))?;
    parse_join_response(&body, &payload.device_id_path)
}

pub fn join_server(
    server: &str,
    control_port: u16,
    token: &str,
    pub_key: &str,
    name: &str,
) -> JoinResponse {
    match try_join_server(server, control_port, token, pub_key, name) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[vpn-client] {}", e);
            std::process::exit(1);
        }
    }
}

pub fn rekey(
    server: &str,
    control_port: u16,
    token: &str,
    old_pub_key: &str,
    new_pub_key: &str,
) -> Result<(), String> {
    let host = control_host(server, control_port);
    let payload = serde_json::to_string(&serde_json::json!({
        "old_public_key": old_pub_key,
        "new_public_key": new_pub_key,
    })).map_err(|e| format!("encode: {}", e))?;
    let body = request_body(
        &host,
        &HttpRequest::post_json(&host, REKEY_PATH, &payload).bearer(token),
    )
    .map_err(|e| format!("rekey failed: {}", e))?;
    if body.contains(REKEY_OK_MARKER) {
        Ok(())
    } else {
        Err(format!("rekey failed: {}", body))
    }
}

#[derive(Clone)]
pub struct ConnectInfo {
    pub server: Option<String>,
    pub relay: Option<String>,
    pub relay_name: Option<String>,
    pub join_url: Option<String>,
}

pub fn join_via_api(url: &str, token: &str, pub_key: &str, name: &str) -> Result<JoinResponse, String> {
    join_via_api_with_routes(url, token, pub_key, name, &[])
}

pub fn join_via_api_with_routes(url: &str, token: &str, pub_key: &str, name: &str, advertise_routes: &[String]) -> Result<JoinResponse, String> {
    let payload = build_join_payload(pub_key, name, advertise_routes)?;

    let parsed = url.strip_prefix("https://").ok_or("join_url must be https")?;
    let (host, path) = parsed.split_once('/').unwrap_or((parsed, DEFAULT_JOIN_PATH));
    let path = format!("/{}", path);

    let body = request_body(
        &https_host_port(host),
        &HttpRequest::post_json(host, &path, &payload.body).bearer(token),
    )
    .map_err(|e| format!("join failed: {}", e))?;
    parse_join_response(&body, &payload.device_id_path)
}

pub fn fetch_connect_info(token: &str) -> Option<ConnectInfo> {
    let api_host = std::env::var(API_HOST_ENV).unwrap_or_else(|_| DEFAULT_API_HOST.to_string());
    let body = request_body(
        &https_host_port(&api_host),
        &HttpRequest::get(&api_host, CONNECT_INFO_PATH).bearer(token),
    )
    .map_err(|e| {
        eprintln!("[nexguard] connect-info: {}", e);
        e
    })
    .ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    Some(ConnectInfo {
        server: json["server"].as_str().map(|s| s.to_string()),
        relay: json["relay"].as_str().map(|s| s.to_string()),
        relay_name: json["relay_name"].as_str().map(|s| s.to_string()),
        join_url: json["join_url"].as_str().map(|s| s.to_string()),
    })
}

#[derive(Clone, Default)]
pub struct GeoInfo {
    pub ip: String,
    pub country: String,
    pub city: String,
    pub region: String,
    pub isp: String,
}

const GEO_HOST: &str = "ipapi.co";
const GEO_PATH: &str = "/json/";

pub fn fetch_geo_info() -> Option<GeoInfo> {
    let body = https_get_text(GEO_HOST, GEO_PATH)?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    Some(GeoInfo {
        ip: v.get("ip").and_then(|x| x.as_str())?.to_string(),
        country: v.get("country_name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        city: v.get("city").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        region: v.get("region").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        isp: v.get("org").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    })
}

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
    cleanup_previous_update();
    let body = https_get_text(VERSION_URL_HOST, VERSION_URL_PATH)?;
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

const MIN_BINARY_SIZE: usize = 1000;
const SIGNATURE_SUFFIX: &str = ".sig";
const SIGNATURE_HEX_LEN: usize = 128;

pub fn download_update(url: &str) -> Result<Vec<u8>, String> {
    let (host, path) = parse_url(url)?;
    let body = download_tls(&host, &path)?;
    if body.len() < MIN_BINARY_SIZE || body.starts_with(b"<html") || body.starts_with(b"<!DOCTYPE") {
        return Err("download returned HTML, not a binary".into());
    }
    let sig_path = format!("{}{}", path, SIGNATURE_SUFFIX);
    let sig_raw = download_tls(&host, &sig_path)
        .map_err(|e| format!("missing signature {}: {}", sig_path, e))?;
    let sig_text = std::str::from_utf8(&sig_raw).unwrap_or("").trim();
    let sig_bytes = if sig_text.len() == SIGNATURE_HEX_LEN {
        hex::decode(sig_text).map_err(|e| format!("bad signature hex: {}", e))?
    } else {
        sig_raw
    };
    verify_signature(&body, &sig_bytes)?;
    Ok(body)
}

fn download_tls(host: &str, path: &str) -> Result<Vec<u8>, String> {
    let (status, body) = send_request(
        &https_host_port(host),
        &HttpRequest::get(host, path),
        &DOWNLOAD_TRANSPORT,
    )?;
    if status != 200 {
        return Err(response_error(status, &String::from_utf8_lossy(&body)));
    }
    Ok(body)
}

const UPDATE_TMP_SUFFIX: &str = ".update";
const UPDATE_OLD_SUFFIX: &str = ".old";

fn suffixed_path(exe: &Path, suffix: &str) -> PathBuf {
    let mut name = exe.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

pub fn cleanup_previous_update() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(suffixed_path(&exe, UPDATE_OLD_SUFFIX));
    }
}

pub fn self_update(url: &str) -> Result<(), String> {
    cleanup_previous_update();
    let binary = download_update(url)?;
    let exe = std::env::current_exe().map_err(|e| format!("current exe: {}", e))?;
    let tmp = suffixed_path(&exe, UPDATE_TMP_SUFFIX);
    let old = suffixed_path(&exe, UPDATE_OLD_SUFFIX);

    std::fs::write(&tmp, &binary).map_err(|e| format!("write tmp: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }

    if let Err(e) = std::fs::rename(&exe, &old) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("stage current binary: {}", e));
    }

    if let Err(e) = std::fs::rename(&tmp, &exe) {
        let _ = std::fs::rename(&old, &exe);
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("replace: {}", e));
    }

    let _ = std::fs::remove_file(&old);
    Ok(())
}

pub fn restart_self() -> ! {
    let exe = std::env::current_exe().expect("current exe");
    let args: Vec<String> = std::env::args().collect();
    eprintln!("[nexguard] restarting...");
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

fn version_parts(version: &str) -> (Vec<u32>, Option<String>) {
    let trimmed = version.trim().trim_start_matches('v');
    let (base, pre) = match trimmed.split_once('-') {
        Some((b, p)) => (b, Some(p.to_string())),
        None => (trimmed, None),
    };
    let numbers = base
        .split('.')
        .map(|p| p.trim().parse::<u32>().unwrap_or(0))
        .collect();
    (numbers, pre)
}

fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (a_num, a_pre) = version_parts(a);
    let (b_num, b_pre) = version_parts(b);
    for i in 0..a_num.len().max(b_num.len()) {
        let ord = a_num.get(i).copied().unwrap_or(0).cmp(&b_num.get(i).copied().unwrap_or(0));
        if ord != Ordering::Equal {
            return ord;
        }
    }
    match (a_pre, b_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => x.cmp(&y),
    }
}

fn version_newer(latest: &str, current: &str) -> bool {
    version_cmp(latest, current) == std::cmp::Ordering::Greater
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

fn control_host(server: &str, control_port: u16) -> String {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return format!("{}:{}", addr.ip(), control_port);
    }
    if let Some((host, _)) = server.rsplit_once(':') {
        return format!("{}:{}", host, control_port);
    }
    format!("{}:{}", server, control_port)
}

pub fn try_parse_endpoint(server: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(SocketAddr::new(addr.ip(), 51820));
    }
    let resolve_target = if server.contains(':') { server.to_string() } else { format!("{}:51820", server) };
    let addr = resolve_target.to_socket_addrs()
        .map_err(|e| format!("resolve {}: {}", server, e))?
        .next()
        .ok_or_else(|| format!("no address for {}", server))?;
    Ok(SocketAddr::new(addr.ip(), 51820))
}

pub fn parse_endpoint(server: &str) -> SocketAddr {
    match try_parse_endpoint(server) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("[vpn-client] {}", e);
            std::process::exit(1);
        }
    }
}
