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
}

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
