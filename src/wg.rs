use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};

use crate::tun::TunDevice;

macro_rules! log {
    ($($arg:tt)*) => {
        let _ = std::io::Write::write_fmt(&mut std::io::stderr(), format_args!($($arg)*));
        let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\n");
    };
}

const MAX_PACKET: usize = 65535;
const WG_BUF_SIZE: usize = MAX_PACKET + 148;
const TIMER_TICK_MS: u128 = 250;
const STATS_INTERVAL_SECS: u64 = 30;
const TLS_READ_TIMEOUT: Duration = Duration::from_millis(5);
const TLS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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

fn pseudo_random_index(n: usize) -> usize {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as usize;
    let pid = std::process::id() as usize;
    (nanos.wrapping_mul(2654435761).wrapping_add(pid)) % n.max(1)
}

fn pick_random_sni() -> &'static str {
    SNI_POOL[pseudo_random_index(SNI_POOL.len())]
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
        self.inner.verify_server_cert(end_entity, intermediates, &self.real_name, ocsp_response, now)
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

pub struct WgState {
    pub tunn: Tunn,
    pub server_pub_key: boringtun::x25519::PublicKey,
}

pub fn connect_relay(
    relay_addr: &str,
    server_name: &str,
    token: &str,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let real_host = relay_addr.split(':').next().unwrap_or("");
    let real_host_owned = if real_host.is_empty() || real_host.parse::<std::net::IpAddr>().is_ok() {
        SNI_POOL[0].to_string()
    } else {
        real_host.to_string()
    };
    let real_name = rustls::pki_types::ServerName::try_from(real_host_owned.clone())
        .map_err(|e| format!("real name: {}", e))?;

    let inner_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| format!("verifier: {}", e))?;
    let verifier = Arc::new(LooseHostnameVerifier {
        inner: inner_verifier,
        real_name,
    });

    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let fake_sni = pick_random_sni();
    let sni = rustls::pki_types::ServerName::try_from(fake_sni.to_string())
        .map_err(|e| format!("sni: {}", e))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), sni)
        .map_err(|e| format!("tls: {}", e))?;

    let socket_addr: SocketAddr = {
        use std::net::ToSocketAddrs;
        relay_addr.parse().or_else(|_|
            relay_addr.to_socket_addrs().map_err(|e| format!("{}", e)).and_then(|mut a| a.next().ok_or_else(|| "no address".into()))
        ).or_else(|_: String|
            format!("{}:443", relay_addr).to_socket_addrs().map_err(|e| format!("{}", e)).and_then(|mut a| a.next().ok_or_else(|| "no address".into()))
        ).map_err(|e| format!("resolve relay {}: {}", relay_addr, e))?
    };

    let jitter_ms = (pseudo_random_index(150) + 20) as u64;
    std::thread::sleep(Duration::from_millis(jitter_ms));

    let tcp = TcpStream::connect_timeout(&socket_addr, TLS_CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {}: {}", relay_addr, e))?;
    tcp.set_nodelay(true).ok();

    let mut tls = rustls::StreamOwned::new(conn, tcp);

    let upgrade = format!(
        "GET /relay HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: nexguard\r\n\
         Connection: Upgrade\r\n\
         X-NexGuard-Server: {}\r\n\
         X-NexGuard-Token: {}\r\n\
         \r\n",
        relay_addr, server_name, token
    );
    tls.write_all(upgrade.as_bytes()).map_err(|e| format!("relay write: {}", e))?;
    tls.flush().map_err(|e| format!("relay flush: {}", e))?;

    let mut resp_buf = [0u8; 1024];
    let mut total = 0;
    tls.sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
    tls.sock.set_write_timeout(Some(Duration::from_secs(5))).ok();
    loop {
        match tls.read(&mut resp_buf[total..]) {
            Ok(0) => return Err("relay: connection closed during handshake".into()),
            Ok(n) => {
                total += n;
                let resp = std::str::from_utf8(&resp_buf[..total]).unwrap_or("");
                if resp.contains("\r\n\r\n") {
                    if !resp.contains("101") {
                        return Err(format!("relay rejected: {}", resp.lines().next().unwrap_or("")));
                    }
                    break;
                }
                if total >= resp_buf.len() {
                    return Err("relay: response too large".into());
                }
            }
            Err(e) => return Err(format!("relay read: {}", e)),
        }
    }

    tls.sock.set_read_timeout(Some(TLS_READ_TIMEOUT)).ok();
    Ok(tls)
}

pub struct RekeyCtx {
    pub server: String,
    pub control_port: u16,
    pub token: String,
    pub private_key: Arc<Mutex<[u8; 32]>>,
}

const REKEY_INTERVAL_SECS: u64 = 24 * 3600;

pub fn run_data_plane_tls<S: Read + Write>(
    tun: &TunDevice,
    tls: &mut S,
    tunnel: &Mutex<WgState>,
    tx: &AtomicU64,
    rx: &AtomicU64,
    shutdown: &AtomicBool,
    mesh: Option<&crate::mesh::MeshManager>,
    rekey_ctx: Option<&RekeyCtx>,
) {
    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut tls_buf = [0u8; MAX_PACKET];
    let mut enc_buf = vec![0u8; WG_BUF_SIZE];
    let mut dec_buf = vec![0u8; WG_BUF_SIZE];
    let mut pending = Vec::with_capacity(MAX_PACKET);
    let mut write_buf = Vec::with_capacity(MAX_PACKET);
    let mut last_tick = std::time::Instant::now();
    let mut last_stats = std::time::Instant::now();
    let mut last_rekey = std::time::Instant::now();
    let mut last_health = std::time::Instant::now();
    let mut last_rx_check = rx.load(Ordering::Relaxed);
    let mut stall_count: u32 = 0;

    loop {
        if shutdown.load(Ordering::Relaxed) { break; }
        let mut did_work = false;
        write_buf.clear();

        for _ in 0..64 {
            match tun.read_packet(&mut tun_buf) {
                Ok(n) if n > 0 => {
                    did_work = true;
                    let sent_via_mesh = if let Some(m) = mesh {
                        if n >= 20 {
                            let dst_ip = u32::from_be_bytes([tun_buf[16], tun_buf[17], tun_buf[18], tun_buf[19]]);
                            m.try_send(&tun_buf[..n], dst_ip)
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !sent_via_mesh {
                        let mut wg = tunnel.lock().unwrap();
                        if let TunnResult::WriteToNetwork(data) = wg.tunn.encapsulate(&tun_buf[..n], &mut enc_buf) {
                            write_buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                            write_buf.extend_from_slice(data);
                            tx.fetch_add(data.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
                Ok(_) => break,
                Err(_) => break,
            }
        }

        if let Some(m) = mesh {
            m.recv_and_process(tun);
        }

        // Flush batched TLS writes
        if !write_buf.is_empty() {
            match tls.write_all(&write_buf) {
                Ok(()) => { let _ = tls.flush(); }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    log!("[vpn-client] tls write error: {}", e);
                    break;
                }
            }
        }

        // TLS → WireGuard decrypt → TUN
        match tls.read(&mut tls_buf) {
            Ok(0) => break,
            Ok(n) => {
                did_work = true;
                pending.extend_from_slice(&tls_buf[..n]);
                write_buf.clear();
                while pending.len() >= 2 {
                    let pkt_len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                    if pkt_len == 0 || pkt_len > 65535 { pending.clear(); break; }
                    if pending.len() < 2 + pkt_len { break; }

                    let mut wg = tunnel.lock().unwrap();
                    match wg.tunn.decapsulate(None, &pending[2..2 + pkt_len], &mut dec_buf) {
                        TunnResult::WriteToTunnelV4(payload, _)
                        | TunnResult::WriteToTunnelV6(payload, _) => {
                            let _ = tun.write_packet(payload);
                            rx.fetch_add(pkt_len as u64, Ordering::Relaxed);
                        }
                        TunnResult::WriteToNetwork(resp) => {
                            write_buf.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                            write_buf.extend_from_slice(resp);
                            loop {
                                match wg.tunn.decapsulate(None, &[], &mut dec_buf) {
                                    TunnResult::WriteToNetwork(d) => {
                                        write_buf.extend_from_slice(&(d.len() as u16).to_be_bytes());
                                        write_buf.extend_from_slice(d);
                                    }
                                    TunnResult::WriteToTunnelV4(d, _)
                                    | TunnResult::WriteToTunnelV6(d, _) => {
                                        let _ = tun.write_packet(d);
                                        rx.fetch_add(pkt_len as u64, Ordering::Relaxed);
                                        break;
                                    }
                                    _ => break,
                                }
                            }
                        }
                        _ => {}
                    }
                    pending.drain(..2 + pkt_len);
                }
                if !write_buf.is_empty() {
                    if tls.write_all(&write_buf).is_err() { break; }
                    let _ = tls.flush();
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                log!("[vpn-client] tls read error: {}", e);
                break;
            }
        }

        if last_tick.elapsed().as_millis() >= TIMER_TICK_MS {
            last_tick = std::time::Instant::now();
            let mut wg = tunnel.lock().unwrap();
            if let TunnResult::WriteToNetwork(data) = wg.tunn.update_timers(&mut enc_buf) {
                let mut buf = Vec::with_capacity(2 + data.len());
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
                let _ = tls.write_all(&buf);
                let _ = tls.flush();
            }
            drop(wg);
            if let Some(m) = mesh {
                m.tick();
            }
        }

        if last_stats.elapsed().as_secs() >= STATS_INTERVAL_SECS {
            last_stats = std::time::Instant::now();
            log!("[vpn-client] tx={} rx={} (tls)", fmt_bytes(tx.load(Ordering::Relaxed)), fmt_bytes(rx.load(Ordering::Relaxed)));
        }

        if last_health.elapsed().as_secs() >= 10 {
            last_health = std::time::Instant::now();
            let current_rx = rx.load(Ordering::Relaxed);
            let current_tx = tx.load(Ordering::Relaxed);
            if current_tx > 0 && current_rx == last_rx_check {
                stall_count += 1;
                if stall_count >= 6 {
                    log!("[vpn-client] connection stalled (no rx for 60s), reconnecting");
                    break;
                }
                if stall_count >= 3 {
                    log!("[vpn-client] degraded connection (no rx for {}s)", stall_count * 10);
                }
            } else {
                stall_count = 0;
            }
            last_rx_check = current_rx;
        }

        if let Some(ctx) = rekey_ctx {
            if last_rekey.elapsed().as_secs() >= REKEY_INTERVAL_SECS {
                last_rekey = std::time::Instant::now();
                do_rekey(tunnel, ctx, &mut enc_buf, tls);
            }
        }

        if !did_work {
            std::thread::sleep(std::time::Duration::from_micros(50));
        }
    }
    log!("[vpn-client] shutdown (tls)");
}

fn do_rekey<S: Read + Write>(
    tunnel: &Mutex<WgState>,
    ctx: &RekeyCtx,
    enc_buf: &mut [u8],
    tls: &mut S,
) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let old_key = *ctx.private_key.lock().unwrap();
    let old_secret = boringtun::x25519::StaticSecret::from(old_key);
    let old_pub = boringtun::x25519::PublicKey::from(&old_secret);
    let old_pub_b64 = b64.encode(old_pub.as_bytes());

    let new_key = crate::generate_private_key();
    let new_secret = boringtun::x25519::StaticSecret::from(new_key);
    let new_pub = boringtun::x25519::PublicKey::from(&new_secret);
    let new_pub_b64 = b64.encode(new_pub.as_bytes());

    match crate::api::rekey(&ctx.server, ctx.control_port, &ctx.token, &old_pub_b64, &new_pub_b64) {
        Ok(()) => {
            let server_pub = {
                let wg = tunnel.lock().unwrap();
                wg.server_pub_key
            };
            let new_tunn = boringtun::noise::Tunn::new(
                new_secret, server_pub, None, Some(crate::jittered_keepalive()), 0, None,
            );
            {
                let mut wg = tunnel.lock().unwrap();
                wg.tunn = new_tunn;
            }
            *ctx.private_key.lock().unwrap() = new_key;

            if let Some(home) = dirs_next() {
                let key_path = home.join("client.key");
                let _ = std::fs::write(&key_path, b64.encode(new_key));
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
                }
            }

            let mut wg = tunnel.lock().unwrap();
            if let TunnResult::WriteToNetwork(data) = wg.tunn.update_timers(enc_buf) {
                let mut buf = Vec::with_capacity(2 + data.len());
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
                let _ = tls.write_all(&buf);
                let _ = tls.flush();
            }

            log!("[vpn-client] key rotated successfully");
        }
        Err(e) => {
            log!("[vpn-client] rekey failed: {}", e);
        }
    }
}

fn dirs_next() -> Option<std::path::PathBuf> {
    crate::dirs_next()
}

fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;

    if b < KB {
        format!("{}B", b)
    } else if b < MB {
        format!("{:.1}KB", b as f64 / KB as f64)
    } else {
        format!("{:.1}MB", b as f64 / MB as f64)
    }
}
