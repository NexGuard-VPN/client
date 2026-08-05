use std::io::{Read, Write};
use std::net::SocketAddr;

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
}

pub struct MeshPeerInfo {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub name: String,
}

pub fn get_mesh_peers(server: &str, control_port: u16, token: &str) -> Vec<MeshPeerInfo> {
    let host = control_host(server, control_port);
    let req = format!(
        "GET /api/v1/mesh/peers HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        host, token
    );
    let resp = match try_http_request(&host, &req) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let body_start = match resp.find("\r\n\r\n") {
        Some(pos) => pos + 4,
        None => return Vec::new(),
    };
    parse_mesh_peers_json(&resp[body_start..])
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
    let ver = env!("CARGO_PKG_VERSION");
    let fp = crate::fingerprint::collect();
    let device_id_path = crate::dirs_next().map(|d| d.join("device-hwid")).unwrap_or_default();
    let saved_device_id = std::fs::read_to_string(&device_id_path).unwrap_or_default().trim().to_string();
    let mut payload = serde_json::json!({
        "public_key": pub_key,
        "name": name,
        "version": ver,
        "fingerprint": fp,
        "device_id": saved_device_id,
    });
    if !advertise_routes.is_empty() {
        payload["advertise_routes"] = serde_json::json!(advertise_routes);
    }
    let body = serde_json::to_string(&payload).map_err(|e| format!("encode: {}", e))?;
    let req = format!(
        "POST /api/v1/join HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        host, token, body.len(), body
    );

    let resp = try_http_request(&host, &req)?;
    let body_start = resp.find("\r\n\r\n")
        .ok_or_else(|| "invalid response: no header terminator".to_string())? + 4;

    let join_resp: JoinResponse = serde_json::from_str(&resp[body_start..])
        .map_err(|e| format!("join failed: {} — {}", e, &resp[body_start..]))?;

    if let Some(ref did) = join_resp.device_id {
        if !did.is_empty() {
            let _ = std::fs::write(&device_id_path, did);
        }
    }

    Ok(join_resp)
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
    let body = serde_json::to_string(&serde_json::json!({
        "old_public_key": old_pub_key,
        "new_public_key": new_pub_key,
    })).map_err(|e| format!("encode: {}", e))?;
    let req = format!(
        "POST /api/v1/rekey HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        host, token, body.len(), body
    );
    let resp = try_http_request(&host, &req)?;
    if resp.contains("\"rekeyed\"") {
        Ok(())
    } else {
        Err(format!("rekey failed: {}", resp))
    }
}

fn try_http_request(host: &str, request: &str) -> Result<String, String> {
    use std::net::ToSocketAddrs;
    let addr = host.to_socket_addrs()
        .map_err(|e| format!("resolve {}: {}", host, e))?
        .next()
        .ok_or_else(|| format!("no address for {}", host))?;

    let mut stream = std::net::TcpStream::connect_timeout(
        &addr,
        std::time::Duration::from_secs(10),
    )
    .map_err(|e| format!("connect {}: {}", host, e))?;

    stream.write_all(request.as_bytes())
        .map_err(|e| format!("write {}: {}", host, e))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();

    let mut response = String::new();
    stream.read_to_string(&mut response).ok();
    Ok(response)
}

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
fn read_http_response<R: std::io::Read>(mut r: R) -> Result<(u16, Vec<u8>), String> {
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
            let n = r.read(&mut chunk).map_err(|e| format!("read: {}", e))?;
            if n == 0 { break; }
            body.extend_from_slice(&chunk[..n]);
        }
        body = dechunk(&body);
    } else if let Some(cl) = content_length {
        while body.len() < cl {
            let n = r.read(&mut chunk).map_err(|e| format!("read: {}", e))?;
            if n == 0 { break; }
            body.extend_from_slice(&chunk[..n]);
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

fn http_get_tls_status(host: &str, path: &str) -> Result<(u16, String), String> {
    use std::io::Write;
    ensure_crypto_provider();

    let addr = {
        use std::net::ToSocketAddrs;
        format!("{}:443", host)
            .to_socket_addrs()
            .map_err(|e| format!("resolve {}: {}", host, e))?
            .next()
            .ok_or_else(|| format!("resolve {}: no address", host))?
    };
    let mut tcp = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))
        .map_err(|e| format!("connect {}: {}", host, e))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let server_name: rustls::pki_types::ServerName = host
        .to_string()
        .try_into()
        .map_err(|_| format!("invalid host {}", host))?;
    let mut conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("tls {}: {}", host, e))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: nexguard\r\n\r\n",
        path, host
    );
    tls.write_all(req.as_bytes()).map_err(|e| format!("send: {}", e))?;
    let (status, body) = read_http_response(&mut tls).map_err(|e| format!("read: {}", e))?;
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn http_get_tls(host: &str, path: &str) -> Option<String> {
    let (status, body) = http_get_tls_status(host, path).ok()?;
    if status != 200 {
        return None;
    }
    Some(body)
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
    let ver = env!("CARGO_PKG_VERSION");
    let fp = crate::fingerprint::collect();
    let device_id_path = crate::dirs_next().map(|d| d.join("device-hwid")).unwrap_or_default();
    let saved_device_id = std::fs::read_to_string(&device_id_path).unwrap_or_default().trim().to_string();
    let mut payload = serde_json::json!({
        "public_key": pub_key,
        "name": name,
        "version": ver,
        "fingerprint": fp,
        "device_id": saved_device_id,
    });
    if !advertise_routes.is_empty() {
        payload["advertise_routes"] = serde_json::json!(advertise_routes);
    }
    let body = serde_json::to_string(&payload).map_err(|e| format!("encode: {}", e))?;

    let parsed = url.strip_prefix("https://").ok_or("join_url must be https")?;
    let (host, path) = parsed.split_once('/').unwrap_or((parsed, "api/vpn/join"));
    let path = format!("/{}", path);

    ensure_crypto_provider();
    let addr = {
        use std::net::ToSocketAddrs;
        format!("{}:443", host).to_socket_addrs()
            .map_err(|e| format!("resolve {}: {}", host, e))?
            .next().ok_or_else(|| format!("no addr for {}", host))?
    };
    let mut tcp = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))
        .map_err(|e| format!("connect {}: {}", host, e))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
    );
    let server_name: rustls::pki_types::ServerName = host.to_string().try_into()
        .map_err(|_| "invalid hostname".to_string())?;
    let mut conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("tls: {}", e))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, token, body.len(), body
    );
    use std::io::Write;
    tls.write_all(req.as_bytes()).map_err(|e| format!("write: {}", e))?;
    let (status, body_bytes) = read_http_response(&mut tls)?;
    let body_text = String::from_utf8_lossy(&body_bytes);
    if status != 200 {
        return Err(format!("join failed: HTTP {} — {}", status, body_text));
    }

    let join_resp: JoinResponse = serde_json::from_str(&body_text)
        .map_err(|e| format!("join parse error: {} — {}", e, body_text))?;

    if let Some(ref did) = join_resp.device_id {
        if !did.is_empty() {
            let _ = std::fs::write(&device_id_path, did);
        }
    }
    Ok(join_resp)
}

// try_fetch_connect_info reports why the lookup failed so the UI can tell a
// billing refusal apart from an unreachable network.
pub fn try_fetch_connect_info(token: &str) -> Result<ConnectInfo, String> {
    let api_host = std::env::var("NEXGUARD_API_HOST").unwrap_or_else(|_| "api.nexguard.sh".to_string());
    let path = format!("/api/vpn/connect-info?token={}", token);
    let (status, body) = http_get_tls_status(&api_host, &path)?;
    if status != 200 {
        return Err(connect_info_error(status, &body));
    }
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| "Unexpected response from NexGuard API.".to_string())?;
    Ok(ConnectInfo {
        server: json["server"].as_str().map(|s| s.to_string()),
        relay: json["relay"].as_str().map(|s| s.to_string()),
        relay_name: json["relay_name"].as_str().map(|s| s.to_string()),
        join_url: json["join_url"].as_str().map(|s| s.to_string()),
    })
}

fn connect_info_error(status: u16, body: &str) -> String {
    let detail = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    match status {
        402 => "Subscription is not active. Renew your plan to reconnect.".to_string(),
        401 => "This device token was revoked or has expired.".to_string(),
        404 => "Server not found for this token.".to_string(),
        _ if !detail.is_empty() => format!("NexGuard API error ({}): {}", status, detail),
        _ => format!("NexGuard API error ({}).", status),
    }
}

#[derive(Clone, Default)]
pub struct GeoInfo {
    pub ip: String,
    pub country: String,
    pub city: String,
    pub region: String,
    pub isp: String,
}

pub fn fetch_geo_info(server: &str, control_port: u16, token: &str) -> Option<GeoInfo> {
    let host = control_host(server, control_port);
    let path = "/api/v1/geo";
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        path, host, token,
    );
    let resp = try_http_request(&host, &req).ok()?;
    let v: serde_json::Value = serde_json::from_str(&resp).ok()?;
    Some(GeoInfo {
        ip: v.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        country: v.get("country").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        city: v.get("city").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        region: v.get("region").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        isp: v.get("isp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
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

pub fn download_update(url: &str) -> Result<Vec<u8>, String> {
    let (host, path) = parse_url(url)?;
    let body = download_tls(&host, &path)?;
    if body.len() < 1000 || body.starts_with(b"<html") || body.starts_with(b"<!DOCTYPE") {
        return Err("download returned HTML, not a binary".into());
    }
    let sig_path = format!("{}.sig", path);
    let sig_raw = download_tls(&host, &sig_path)
        .map_err(|e| format!("missing signature {}: {}", sig_path, e))?;
    let sig_text = std::str::from_utf8(&sig_raw).unwrap_or("").trim();
    let sig_bytes = if sig_text.len() == 128 {
        hex::decode(sig_text).map_err(|e| format!("bad signature hex: {}", e))?
    } else {
        sig_raw
    };
    verify_signature(&body, &sig_bytes)?;
    Ok(body)
}

fn download_tls(host: &str, path: &str) -> Result<Vec<u8>, String> {
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
    let (status, body) = read_http_response(&mut tls)?;
    if status != 200 {
        return Err(format!("HTTP {}", status));
    }
    Ok(body)
}

pub fn self_update(url: &str) -> Result<(), String> {
    let binary = download_update(url)?;
    let exe = std::env::current_exe()
        .map_err(|e| format!("current exe: {}", e))?;

    let tmp = exe.with_extension("update");
    std::fs::write(&tmp, &binary)
        .map_err(|e| format!("write tmp: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }

    std::fs::rename(&tmp, &exe)
        .map_err(|e| format!("replace: {}", e))?;
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

fn control_host(server: &str, control_port: u16) -> String {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return format!("{}:{}", addr.ip(), control_port);
    }
    if let Some((host, _)) = server.rsplit_once(':') {
        return format!("{}:{}", host, control_port);
    }
    format!("{}:{}", server, control_port)
}

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
    #[serde(default)]
    pub server_id: String,
    #[serde(default)]
    pub tunnel_name: String,
    #[serde(default)]
    pub tunnel_server: String,
    #[serde(default)]
    pub email: String,
}

#[derive(serde::Deserialize, Clone)]
#[allow(dead_code)]
pub struct DeviceTokenResp {
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct ConnectBundle {
    pub device_jwt: String,
    pub server_id: String,
    pub relay: String,
    pub relay_name: String,
    pub email: String,
}

fn api_host() -> String {
    std::env::var("NEXGUARD_API_HOST").unwrap_or_else(|_| "api.nexguard.sh".to_string())
}

fn http_post_tls_json(host: &str, path: &str, body: &str, auth_token: Option<&str>) -> Result<(u16, String), String> {
    use std::io::Write;
    ensure_crypto_provider();

    let addr = {
        use std::net::ToSocketAddrs;
        format!("{}:443", host).to_socket_addrs()
            .map_err(|e| format!("resolve {}: {}", host, e))?
            .next().ok_or_else(|| format!("no address for {}", host))?
    };
    let mut tcp = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))
        .map_err(|e| format!("connect {}: {}", host, e))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
    );
    let server_name: rustls::pki_types::ServerName = host.to_string().try_into()
        .map_err(|_| format!("invalid hostname {}", host))?;
    let mut conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("tls: {}", e))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let auth_header = match auth_token {
        Some(t) => format!("Authorization: Bearer {}\r\n", t),
        None => String::new(),
    };
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: nexguard\r\n\r\n{}",
        path, host, auth_header, body.len(), body
    );
    tls.write_all(req.as_bytes()).map_err(|e| format!("write: {}", e))?;
    let (status, body_bytes) = read_http_response(&mut tls)?;
    Ok((status, String::from_utf8_lossy(&body_bytes).into_owned()))
}

pub fn request_device_login() -> Result<DeviceLoginResp, String> {
    let host = api_host();
    let (status, body) = http_post_tls_json(&host, "/api/auth/device", "{}", None)?;
    if status != 200 {
        return Err(format!("device login failed: HTTP {} — {}", status, body));
    }
    serde_json::from_str(&body).map_err(|e| format!("parse device login: {} — {}", e, body))
}

pub fn poll_device_login(device_token: &str) -> Result<Option<ConnectBundle>, String> {
    let host = api_host();
    let path = format!("/api/auth/device/check?token={}", device_token);
    let (status, body) = http_get_tls_status(&host, &path)?;
    if status != 200 {
        return Err(format!("device check failed: HTTP {} — {}", status, body));
    }
    let resp: DeviceCheckResp = serde_json::from_str(&body)
        .map_err(|e| format!("parse device check: {} — {}", e, body))?;
    if resp.status != "confirmed" {
        return Ok(None);
    }
    let device_name = crate::generate_client_name();
    let create_body = serde_json::json!({ "name": device_name }).to_string();
    let create_path = format!("/api/vpn/servers/{}/devices", resp.server_id);
    let (status, body) = http_post_tls_json(&host, &create_path, &create_body, Some(&resp.token))?;
    if status != 201 && status != 200 {
        return Err(format!("create device token failed: HTTP {} — {}", status, body));
    }
    let dev_resp: DeviceTokenResp = serde_json::from_str(&body)
        .map_err(|e| format!("parse device token: {} — {}", e, body))?;
    Ok(Some(ConnectBundle {
        device_jwt: dev_resp.token,
        server_id: resp.server_id,
        relay: resp.tunnel_server,
        relay_name: resp.tunnel_name,
        email: resp.email,
    }))
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

pub fn report_endpoint(server: &str, control_port: u16, token: &str, pub_key: &str, endpoint: &str) -> Result<(), String> {
    let host = control_host(server, control_port);
    let body = serde_json::json!({ "endpoint": endpoint }).to_string();
    let path = format!("/api/v1/peers/{}/endpoint", pub_key);
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, token, body.len(), body
    );
    let resp = try_http_request(&host, &req)?;
    if resp.contains("\"updated\"") || resp.contains("200") {
        Ok(())
    } else {
        Err(format!("report endpoint failed: {}", resp))
    }
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
