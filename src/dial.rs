use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

const READ_TIMEOUT: Duration = Duration::from_millis(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_BUF: usize = 1024;
const SWITCHING_PROTOCOLS: &str = "101";
const HEADER_END: &str = "\r\n\r\n";
const JITTER_FLOOR_MS: u64 = 20;
const JITTER_SPREAD_MS: usize = 150;
const IMPLICIT_PORT: u16 = 443;

const SNI_POOL: &[&str] = &[
    "www.cloudflare.com",
    "static.cloudflareinsights.com",
    "ajax.cloudflare.com",
    "cdn.shopify.com",
    "fonts.googleapis.com",
    "ajax.googleapis.com",
    "i.ytimg.com",
    "platform.twitter.com",
    "connect.facebook.net",
    "m.media-amazon.com",
    "static.xx.fbcdn.net",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
];

fn pick_random_sni() -> &'static str {
    SNI_POOL[crate::rng::index(SNI_POOL.len())]
}

#[derive(Debug)]
struct LooseHostnameVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    real_name: rustls::pki_types::ServerName<'static>,
}

impl rustls::client::danger::ServerCertVerifier for LooseHostnameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.real_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub type UpgradedStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn resolve(addr: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    if let Ok(parsed) = addr.parse::<SocketAddr>() {
        return Ok(parsed);
    }
    let with_port = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:{}", addr, IMPLICIT_PORT)
    };
    with_port
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {}", addr, e))?
        .next()
        .ok_or_else(|| format!("resolve {}: no address", addr))
}

fn tls_config(host: &str) -> Result<rustls::ClientConfig, String> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let bare_host = host.split(':').next().unwrap_or_default();
    let real_host = if bare_host.is_empty() || bare_host.parse::<std::net::IpAddr>().is_ok() {
        SNI_POOL[0].to_string()
    } else {
        bare_host.to_string()
    };
    let real_name = rustls::pki_types::ServerName::try_from(real_host)
        .map_err(|e| format!("name {}: {}", host, e))?;
    let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| format!("verifier: {}", e))?;

    Ok(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(LooseHostnameVerifier { inner, real_name }))
            .with_no_client_auth(),
    )
}

/// Opens a TLS connection whose SNI names an unrelated popular host, then asks
/// the peer to switch protocols. The certificate is still verified against the
/// address we dialled, so the decoy SNI costs nothing in trust.
pub fn upgrade(
    host: &str,
    path: &str,
    protocol: &str,
    headers: &[(&str, &str)],
) -> Result<UpgradedStream, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = tls_config(host)?;
    let sni = rustls::pki_types::ServerName::try_from(pick_random_sni().to_string())
        .map_err(|e| format!("sni: {}", e))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), sni)
        .map_err(|e| format!("tls {}: {}", host, e))?;
    let address = resolve(host)?;

    let jitter = JITTER_FLOOR_MS + crate::rng::index(JITTER_SPREAD_MS) as u64;
    std::thread::sleep(Duration::from_millis(jitter));

    let tcp = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {}: {}", host, e))?;
    tcp.set_nodelay(true).ok();

    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.sock.set_read_timeout(Some(HANDSHAKE_READ_TIMEOUT)).ok();
    tls.sock.set_write_timeout(Some(HANDSHAKE_WRITE_TIMEOUT)).ok();

    let extra: String = headers.iter().map(|(k, v)| format!("{}: {}\r\n", k, v)).collect();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: {}\r\nConnection: Upgrade\r\n{}\r\n",
        path, host, protocol, extra
    );
    tls.write_all(request.as_bytes()).map_err(|e| format!("send: {}", e))?;
    tls.flush().map_err(|e| format!("flush: {}", e))?;

    read_handshake(&mut tls)?;
    tls.sock.set_read_timeout(Some(READ_TIMEOUT)).ok();
    Ok(tls)
}

fn read_handshake(tls: &mut UpgradedStream) -> Result<(), String> {
    let mut buf = [0u8; HANDSHAKE_BUF];
    let mut filled = 0;
    loop {
        match tls.read(&mut buf[filled..]) {
            Ok(0) => return Err("closed during handshake".into()),
            Ok(n) => {
                filled += n;
                let response = std::str::from_utf8(&buf[..filled]).unwrap_or_default();
                if let Some(head) = response.split(HEADER_END).next().filter(|_| response.contains(HEADER_END)) {
                    if !head.contains(SWITCHING_PROTOCOLS) {
                        return Err(format!("refused: {}", head.lines().next().unwrap_or_default()));
                    }
                    return Ok(());
                }
                if filled >= buf.len() {
                    return Err("handshake response too large".into());
                }
            }
            Err(e) => return Err(format!("read: {}", e)),
        }
    }
}
