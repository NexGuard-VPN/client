use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use boringtun::noise::{Tunn, TunnResult};

use crate::tun::TunDevice;

const MAX_PACKET: usize = 65535;
const TIMER_TICK_MS: u128 = 250;
const STATS_INTERVAL_SECS: u64 = 30;

pub struct WgState {
    pub tunn: Tunn,
    pub endpoint: SocketAddr,
}

pub fn run_data_plane(
    tun: &TunDevice,
    udp: &UdpSocket,
    tunnel: &Mutex<WgState>,
    tx: &AtomicU64,
    rx: &AtomicU64,
    shutdown: &AtomicBool,
    mesh: Option<&crate::mesh::MeshManager>,
) {
    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut udp_buf = vec![0u8; MAX_PACKET];
    let mut enc_buf = vec![0u8; MAX_PACKET];
    let mut dec_buf = vec![0u8; MAX_PACKET];
    let mut last_tick = std::time::Instant::now();
    let mut last_stats = std::time::Instant::now();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut did_work = false;

        if let Ok(n) = tun.read_packet(&mut tun_buf) {
            if n > 0 {
                did_work = true;
                let sent_via_mesh = if let Some(ref m) = mesh {
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
                    if let TunnResult::WriteToNetwork(data) =
                        wg.tunn.encapsulate(&tun_buf[..n], &mut enc_buf)
                    {
                        let _ = udp.send_to(data, wg.endpoint);
                        tx.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                }
            }
        }

        match udp.recv_from(&mut udp_buf) {
            Ok((n, _)) => {
                did_work = true;
                let mut wg = tunnel.lock().unwrap();
                handle_udp_packet(&mut wg, udp, tun, &udp_buf[..n], &mut dec_buf, rx, n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }

        if let Some(ref m) = mesh {
            m.recv_and_process(tun);
        }

        if last_tick.elapsed().as_millis() >= TIMER_TICK_MS {
            last_tick = std::time::Instant::now();
            let mut wg = tunnel.lock().unwrap();
            if let TunnResult::WriteToNetwork(data) = wg.tunn.update_timers(&mut enc_buf) {
                let _ = udp.send_to(data, wg.endpoint);
            }
            if let Some(ref m) = mesh {
                m.tick();
            }
        }

        if last_stats.elapsed().as_secs() >= STATS_INTERVAL_SECS {
            last_stats = std::time::Instant::now();
            eprintln!(
                "[vpn-client] tx={} rx={}",
                fmt_bytes(tx.load(Ordering::Relaxed)),
                fmt_bytes(rx.load(Ordering::Relaxed))
            );
        }

        if !did_work {
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
    }

    eprintln!("[vpn-client] shutdown");
}

fn handle_udp_packet(
    wg: &mut WgState,
    udp: &UdpSocket,
    tun: &TunDevice,
    data: &[u8],
    dec_buf: &mut [u8],
    rx: &AtomicU64,
    n: usize,
) {
    match wg.tunn.decapsulate(None, data, dec_buf) {
        TunnResult::WriteToTunnelV4(payload, _) => {
            let _ = tun.write_packet(payload);
            rx.fetch_add(n as u64, Ordering::Relaxed);
        }
        TunnResult::WriteToNetwork(resp) => {
            let _ = udp.send_to(resp, wg.endpoint);
            drain_pending(wg, udp, tun, dec_buf, rx, n);
        }
        _ => {}
    }
}

fn drain_pending(
    wg: &mut WgState,
    udp: &UdpSocket,
    tun: &TunDevice,
    dec_buf: &mut [u8],
    rx: &AtomicU64,
    n: usize,
) {
    loop {
        match wg.tunn.decapsulate(None, &[], dec_buf) {
            TunnResult::WriteToNetwork(data) => {
                let _ = udp.send_to(data, wg.endpoint);
            }
            TunnResult::WriteToTunnelV4(data, _) => {
                let _ = tun.write_packet(data);
                rx.fetch_add(n as u64, Ordering::Relaxed);
                break;
            }
            _ => break,
        }
    }
}

pub fn run_data_plane_tls<S: Read + Write>(
    tun: &TunDevice,
    tls: &mut S,
    tunnel: &Mutex<WgState>,
    tx: &AtomicU64,
    rx: &AtomicU64,
    shutdown: &AtomicBool,
) {
    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut tls_buf = [0u8; 4096];
    let mut enc_buf = vec![0u8; MAX_PACKET];
    let mut dec_buf = vec![0u8; MAX_PACKET];
    let mut pending = Vec::new();
    let mut last_tick = std::time::Instant::now();
    let mut last_stats = std::time::Instant::now();

    loop {
        if shutdown.load(Ordering::Relaxed) { break; }
        let mut did_work = false;

        // TUN → WireGuard encrypt → TLS
        if let Ok(n) = tun.read_packet(&mut tun_buf) {
            if n > 0 {
                did_work = true;
                let mut wg = tunnel.lock().unwrap();
                if let TunnResult::WriteToNetwork(data) = wg.tunn.encapsulate(&tun_buf[..n], &mut enc_buf) {
                    let len = (data.len() as u16).to_be_bytes();
                    let _ = tls.write_all(&len);
                    let _ = tls.write_all(data);
                    let _ = tls.flush();
                    tx.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
        }

        // TLS → WireGuard decrypt → TUN
        match tls.read(&mut tls_buf) {
            Ok(0) => break,
            Ok(n) => {
                did_work = true;
                pending.extend_from_slice(&tls_buf[..n]);
                while pending.len() >= 2 {
                    let pkt_len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                    if pkt_len == 0 || pkt_len > 65535 { pending.clear(); break; }
                    if pending.len() < 2 + pkt_len { break; }
                    let pkt = pending[2..2 + pkt_len].to_vec();
                    pending.drain(..2 + pkt_len);

                    let mut wg = tunnel.lock().unwrap();
                    match wg.tunn.decapsulate(None, &pkt, &mut dec_buf) {
                        TunnResult::WriteToTunnelV4(payload, _) => {
                            let _ = tun.write_packet(payload);
                            rx.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                        }
                        TunnResult::WriteToNetwork(resp) => {
                            let len = (resp.len() as u16).to_be_bytes();
                            let _ = tls.write_all(&len);
                            let _ = tls.write_all(resp);
                            let _ = tls.flush();
                            // drain pending WG packets
                            loop {
                                match wg.tunn.decapsulate(None, &[], &mut dec_buf) {
                                    TunnResult::WriteToNetwork(d) => {
                                        let l = (d.len() as u16).to_be_bytes();
                                        let _ = tls.write_all(&l);
                                        let _ = tls.write_all(d);
                                    }
                                    TunnResult::WriteToTunnelV4(d, _) => {
                                        let _ = tun.write_packet(d);
                                        rx.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                                        break;
                                    }
                                    _ => break,
                                }
                            }
                            let _ = tls.flush();
                        }
                        _ => {}
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }

        // Timer tick
        if last_tick.elapsed().as_millis() >= TIMER_TICK_MS {
            last_tick = std::time::Instant::now();
            let mut wg = tunnel.lock().unwrap();
            if let TunnResult::WriteToNetwork(data) = wg.tunn.update_timers(&mut enc_buf) {
                let len = (data.len() as u16).to_be_bytes();
                let _ = tls.write_all(&len);
                let _ = tls.write_all(data);
                let _ = tls.flush();
            }
        }

        if last_stats.elapsed().as_secs() >= STATS_INTERVAL_SECS {
            last_stats = std::time::Instant::now();
            eprintln!("[vpn-client] tx={} rx={} (tls)", fmt_bytes(tx.load(Ordering::Relaxed)), fmt_bytes(rx.load(Ordering::Relaxed)));
        }

        if !did_work {
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
    }
    eprintln!("[vpn-client] shutdown (tls)");
}

use std::io::{Read, Write};

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
