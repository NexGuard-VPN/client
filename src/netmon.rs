use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// Watches the underlying network path and wall-clock jumps (sleep/wake) so
/// reconnect logic reacts immediately instead of waiting out a backoff timer.
///
/// The path signature is the source address the OS picks for a UDP connect
/// toward `target` — no packets are sent. While a session is up the target
/// must be the relay/server endpoint: its host route stays on the physical
/// interface, so the signature tracks the real uplink even when the default
/// route points at the tunnel.
pub struct NetMonitor {
    epoch: Arc<AtomicU64>,
    target: Arc<Mutex<String>>,
}

impl NetMonitor {
    pub fn start() -> Self {
        let epoch = Arc::new(AtomicU64::new(0));
        let target = Arc::new(Mutex::new(String::new()));
        let ep = Arc::clone(&epoch);
        let tg = Arc::clone(&target);
        std::thread::spawn(move || {
            let mut resolved: Option<(String, SocketAddr)> = None;
            let mut last_sig = String::new();
            let mut last_wall = SystemTime::now();
            loop {
                std::thread::sleep(Duration::from_secs(2));
                let wall = SystemTime::now();
                let drift = wall
                    .duration_since(last_wall)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                last_wall = wall;

                // Resolve only when the target changes; a lookup every tick
                // would put needless DNS traffic on the wire.
                let target = tg.lock().unwrap().clone();
                if resolved.as_ref().map(|(t, _)| t != &target).unwrap_or(true) {
                    resolved = resolve(&target).map(|a| (target.clone(), a));
                }
                let Some((_, addr)) = resolved else { continue };

                let sig = signature(addr);
                let path_changed = !sig.is_empty() && !last_sig.is_empty() && sig != last_sig;
                let woke_from_sleep = drift > 8;
                if path_changed || woke_from_sleep {
                    ep.fetch_add(1, Ordering::Relaxed);
                }
                if !sig.is_empty() {
                    last_sig = sig;
                }
            }
        });
        Self { epoch, target }
    }

    pub fn set_target(&self, addr: &str) {
        let mut t = self.target.lock().unwrap();
        if *t != addr {
            *t = addr.to_string();
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// Sleep up to `dur`, returning early (true) if the network path changed.
    pub fn wait(&self, dur: Duration) -> bool {
        let start_epoch = self.epoch();
        let deadline = Instant::now() + dur;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(300));
            if self.epoch() != start_epoch {
                return true;
            }
        }
        false
    }
}

fn resolve(target: &str) -> Option<SocketAddr> {
    if target.is_empty() {
        return "1.1.1.1:53".parse().ok();
    }
    let with_port = if target.matches(':').count() == 1
        && target.rsplit(':').next().map(|p| p.parse::<u16>().is_ok()) == Some(true)
    {
        target.to_string()
    } else {
        format!("{}:53", target)
    };
    with_port.to_socket_addrs().ok().and_then(|mut a| a.next())
}

fn signature(addr: SocketAddr) -> String {
    UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .and_then(|s| {
            s.connect(addr)?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_default()
}
