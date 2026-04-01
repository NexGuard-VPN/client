use std::io::{Read, Write};
use std::net::SocketAddr;

#[derive(serde::Deserialize)]
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

pub fn report_endpoint(server: &str, control_port: u16, token: &str, pubkey: &str, endpoint: &str) {
    let host = control_host(server, control_port);
    let encoded = urlencode(pubkey);
    let body = format!(r#"{{"endpoint":"{}"}}"#, endpoint);
    let req = format!(
        "POST /api/v1/peers/{}/endpoint HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        encoded, host, token, body.len(), body
    );
    let _ = try_http_request(&host, &req);
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

fn urlencode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push('%');
                result.push(char::from(HEX[(b >> 4) as usize]));
                result.push(char::from(HEX[(b & 0xf) as usize]));
            }
        }
    }
    result
}

const HEX: [u8; 16] = *b"0123456789ABCDEF";

pub fn try_join_server(
    server: &str,
    control_port: u16,
    token: &str,
    pub_key: &str,
    name: &str,
) -> Result<JoinResponse, String> {
    let host = control_host(server, control_port);
    let body = format!(r#"{{"public_key":"{}","name":"{}"}}"#, pub_key, name);
    let req = format!(
        "POST /api/v1/join HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        host, token, body.len(), body
    );

    let resp = try_http_request(&host, &req)?;
    let body_start = resp.find("\r\n\r\n")
        .ok_or_else(|| "invalid response: no header terminator".to_string())? + 4;

    serde_json::from_str(&resp[body_start..])
        .map_err(|e| format!("join failed: {} — {}", e, &resp[body_start..]))
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

fn http_get(host: &str, path: &str) -> Option<String> {
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: vpn-client\r\n\r\n",
        path, host
    );
    let resp = try_http_request(&format!("{}:80", host), &req).ok()?;
    let body_start = resp.find("\r\n\r\n")? + 4;
    Some(resp[body_start..].to_string())
}

#[derive(Clone, Default)]
pub struct GeoInfo {
    pub ip: String,
    pub country: String,
    pub city: String,
    pub region: String,
    pub isp: String,
}

pub fn fetch_geo_info() -> Option<GeoInfo> {
    let body = http_get("ip-api.com", "/json/?fields=query,country,city,regionName,isp")?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    Some(GeoInfo {
        ip: v.get("query")?.as_str()?.to_string(),
        country: v.get("country")?.as_str()?.to_string(),
        city: v.get("city")?.as_str()?.to_string(),
        region: v.get("regionName").and_then(|r| r.as_str()).unwrap_or("").to_string(),
        isp: v.get("isp").and_then(|r| r.as_str()).unwrap_or("").to_string(),
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
}

pub fn check_update() -> Option<UpdateInfo> {
    let body = http_get(VERSION_URL_HOST, VERSION_URL_PATH)?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let latest = v.get("client")?.get("version")?.as_str()?;

    let has_update = version_newer(latest, CURRENT_VERSION);
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
    })
}

pub fn download_update(url: &str) -> Result<Vec<u8>, String> {
    let (host, path) = parse_url(url)?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: nexguard-updater\r\n\r\n",
        path, host
    );
    let resp_str = try_http_request(&format!("{}:443", host), &req)
        .or_else(|_| try_http_request(&format!("{}:80", host), &req))?;
    let body_start = resp_str.find("\r\n\r\n")
        .ok_or("invalid response")? + 4;
    Ok(resp_str[body_start..].as_bytes().to_vec())
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

    let backup = exe.with_extension("old");
    let _ = std::fs::remove_file(&backup);
    std::fs::rename(&exe, &backup)
        .map_err(|e| format!("backup: {}", e))?;
    std::fs::rename(&tmp, &exe)
        .map_err(|e| {
            let _ = std::fs::rename(&backup, &exe);
            format!("replace: {}", e)
        })?;
    let _ = std::fs::remove_file(&backup);
    Ok(())
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
