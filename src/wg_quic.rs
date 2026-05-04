use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boringtun::noise::TunnResult;

use crate::tun::TunDevice;
use crate::wg::WgState;

const TLS_SNI: &str = "tunnel.nexguard.sh";
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PACKET: usize = 65535;
const WG_BUF_SIZE: usize = MAX_PACKET + 148;

pub struct QuicTunnel {
    pub tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    pub rx: std::sync::mpsc::Receiver<Vec<u8>>,
    pub closed: Arc<AtomicBool>,
    _runtime: tokio::runtime::Runtime,
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer,
        _: &[rustls::pki_types::CertificateDer],
        _: &rustls::pki_types::ServerName,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn connect_quic_relay(
    relay_addr: &str,
    server_name: &str,
) -> Result<QuicTunnel, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let host = relay_addr.split(':').next().unwrap_or(TLS_SNI);
    let sni_name = if host.parse::<std::net::IpAddr>().is_ok() { TLS_SNI } else { host };

    let socket_addr: SocketAddr = {
        use std::net::ToSocketAddrs;
        relay_addr.parse().or_else(|_|
            relay_addr.to_socket_addrs().map_err(|e| format!("{}", e)).and_then(|mut a| a.next().ok_or_else(|| "no address".into()))
        ).or_else(|_: String|
            format!("{}:443", relay_addr).to_socket_addrs().map_err(|e| format!("{}", e)).and_then(|mut a| a.next().ok_or_else(|| "no address".into()))
        ).map_err(|e| format!("resolve relay {}: {}", relay_addr, e))?
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("tokio rt: {}", e))?;

    let server_name_str = server_name.to_string();
    let sni_string = sni_name.to_string();

    let (tx_to_quic, mut rx_to_quic) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (tx_from_quic_async, rx_from_quic) = std::sync::mpsc::channel::<Vec<u8>>();
    let closed = Arc::new(AtomicBool::new(false));
    let closed_clone = Arc::clone(&closed);

    eprintln!("[quic] dialing {} (sni={})", socket_addr, sni_name);
    let setup = runtime.block_on(async move {
        tokio::time::timeout(QUIC_CONNECT_TIMEOUT, async {
            let mut tls = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h3".to_vec()];

            let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| format!("crypto: {}", e))?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(qcc));
            let mut transport = quinn::TransportConfig::default();
            transport
                .max_concurrent_uni_streams(quinn::VarInt::from_u32(8))
                .max_concurrent_bidi_streams(quinn::VarInt::from_u32(8))
                .keep_alive_interval(Some(Duration::from_secs(15)))
                .datagram_receive_buffer_size(Some(8 * 1024 * 1024))
                .datagram_send_buffer_size(8 * 1024 * 1024);
            client_config.transport_config(Arc::new(transport));

            let bind: SocketAddr = if socket_addr.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
            let mut endpoint = quinn::Endpoint::client(bind).map_err(|e| format!("endpoint: {}", e))?;
            endpoint.set_default_client_config(client_config);

            let connecting = endpoint.connect(socket_addr, &sni_string)
                .map_err(|e| format!("connect: {}", e))?;
            eprintln!("[quic] handshake started, waiting...");
            let conn = connecting.await.map_err(|e| format!("handshake: {}", e))?;
            eprintln!("[quic] connected, opening intro stream");

            let mut send = conn.open_uni().await.map_err(|e| format!("open_uni: {}", e))?;
            let intro = format!("nexguard:{}\n", server_name_str);
            send.write_all(intro.as_bytes()).await.map_err(|e| format!("intro write: {}", e))?;
            send.finish().map_err(|e| format!("intro finish: {}", e))?;
            eprintln!("[quic] intro sent ({})", server_name_str);

            Ok::<quinn::Connection, String>(conn)
        }).await.map_err(|_| "QUIC connect timeout".to_string())?
    })?;

    let conn = setup;
    let conn_send = conn.clone();
    let conn_recv = conn.clone();
    let closed_send = Arc::clone(&closed_clone);
    let closed_recv = Arc::clone(&closed_clone);

    runtime.spawn(async move {
        while let Some(pkt) = rx_to_quic.recv().await {
            if closed_send.load(Ordering::Relaxed) { break; }
            if let Err(e) = conn_send.send_datagram(pkt.into()) {
                eprintln!("[quic] send_datagram: {}", e);
                closed_send.store(true, Ordering::Relaxed);
                break;
            }
        }
    });

    runtime.spawn(async move {
        loop {
            if closed_recv.load(Ordering::Relaxed) { break; }
            match conn_recv.read_datagram().await {
                Ok(bytes) => {
                    if tx_from_quic_async.send(bytes.to_vec()).is_err() { break; }
                }
                Err(e) => {
                    eprintln!("[quic] read_datagram: {}", e);
                    closed_recv.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    });

    Ok(QuicTunnel { tx: tx_to_quic, rx: rx_from_quic, closed, _runtime: runtime })
}

const TIMER_TICK_MS: u128 = 250;
const STATS_INTERVAL_SECS: u64 = 30;

pub fn run_data_plane_quic(
    tun: &TunDevice,
    quic: &QuicTunnel,
    tunnel: &Mutex<WgState>,
    tx: &AtomicU64,
    rx: &AtomicU64,
    shutdown: &AtomicBool,
) {
    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut enc_buf = vec![0u8; WG_BUF_SIZE];
    let mut dec_buf = vec![0u8; WG_BUF_SIZE];
    let mut last_tick = std::time::Instant::now();
    let mut last_stats = std::time::Instant::now();

    loop {
        if shutdown.load(Ordering::Relaxed) || quic.closed.load(Ordering::Relaxed) { break; }
        let mut did_work = false;

        for _ in 0..64 {
            match tun.read_packet(&mut tun_buf) {
                Ok(n) if n > 0 => {
                    did_work = true;
                    let mut wg = tunnel.lock().unwrap();
                    if let TunnResult::WriteToNetwork(data) = wg.tunn.encapsulate(&tun_buf[..n], &mut enc_buf) {
                        if quic.tx.send(data.to_vec()).is_err() {
                            quic.closed.store(true, Ordering::Relaxed);
                            return;
                        }
                        tx.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                }
                _ => break,
            }
        }

        loop {
            match quic.rx.try_recv() {
                Ok(dgram) => {
                    did_work = true;
                    let mut wg = tunnel.lock().unwrap();
                    match wg.tunn.decapsulate(None, &dgram, &mut dec_buf) {
                        TunnResult::WriteToTunnelV4(payload, _)
                        | TunnResult::WriteToTunnelV6(payload, _) => {
                            let _ = tun.write_packet(payload);
                            rx.fetch_add(dgram.len() as u64, Ordering::Relaxed);
                        }
                        TunnResult::WriteToNetwork(resp) => {
                            let _ = quic.tx.send(resp.to_vec());
                            loop {
                                match wg.tunn.decapsulate(None, &[], &mut dec_buf) {
                                    TunnResult::WriteToNetwork(d) => { let _ = quic.tx.send(d.to_vec()); }
                                    _ => break,
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    quic.closed.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }

        if last_tick.elapsed().as_millis() >= TIMER_TICK_MS {
            last_tick = std::time::Instant::now();
            let mut wg = tunnel.lock().unwrap();
            if let TunnResult::WriteToNetwork(data) = wg.tunn.update_timers(&mut enc_buf) {
                let _ = quic.tx.send(data.to_vec());
            }
        }

        if last_stats.elapsed().as_secs() >= STATS_INTERVAL_SECS {
            last_stats = std::time::Instant::now();
            eprintln!("[stats] quic tx={} rx={}", tx.load(Ordering::Relaxed), rx.load(Ordering::Relaxed));
        }

        if !did_work {
            std::thread::sleep(Duration::from_micros(200));
        }
    }
}
