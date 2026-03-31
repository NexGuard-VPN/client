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
    let resp = http_request(&host, &req);
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
    let _ = http_request(&host, &req);
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

pub fn join_server(
    server: &str,
    control_port: u16,
    token: &str,
    pub_key: &str,
    name: &str,
) -> JoinResponse {
    let host = control_host(server, control_port);
    let body = format!(r#"{{"public_key":"{}","name":"{}"}}"#, pub_key, name);
    let req = format!(
        "POST /api/v1/join HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        host, token, body.len(), body
    );

    let resp = http_request(&host, &req);
    let body_start = resp.find("\r\n\r\n").expect("invalid response") + 4;

    serde_json::from_str(&resp[body_start..]).unwrap_or_else(|e| {
        eprintln!("[vpn-client] join failed: {} — {}", e, &resp[body_start..]);
        std::process::exit(1);
    })
}

fn http_request(host: &str, request: &str) -> String {
    let addr: SocketAddr = host.parse().expect("invalid addr");
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.into(),
        std::time::Duration::from_secs(10),
    )
    .unwrap_or_else(|e| {
        eprintln!("[vpn-client] connect {}: {}", host, e);
        std::process::exit(1);
    });

    stream.write_all(request.as_bytes()).expect("write failed");
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();

    let mut response = String::new();
    stream.read_to_string(&mut response).ok();
    response
}

fn control_host(server: &str, control_port: u16) -> String {
    let addr: SocketAddr = server.parse().expect("invalid server");
    format!("{}:{}", addr.ip(), control_port)
}

pub fn parse_endpoint(server: &str) -> SocketAddr {
    let addr: SocketAddr = server.parse().expect("invalid server");
    SocketAddr::new(addr.ip(), 51820)
}
