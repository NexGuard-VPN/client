use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::meshapi::{self, MeshIdentity};
use crate::meshnet::{self, MeshConfig, MeshStatus};
use crate::protocol::{EngineState, SessionView, Snapshot};

const STOP_GRACE: Duration = Duration::from_secs(10);
const STOP_POLL: Duration = Duration::from_millis(100);

fn session_view(status: &MeshStatus) -> SessionView {
    SessionView {
        device_id: status.device_id.clone(),
        name: status.name.clone(),
        address: status.address.clone(),
        network: status.network.clone(),
        dns_suffix: status.dns_suffix.clone(),
        tun_name: status.tun_name.clone(),
        exit_node: status.exit_node.clone(),
        serving_exit: status.serving_exit,
        advertising_exit: status.advertising_exit,
        relay_connected: status.relay_connected.load(Ordering::Relaxed),
        peers: status.peers.lock().map(|p| p.clone()).unwrap_or_default(),
        tx: status.tx.load(Ordering::Relaxed),
        rx: status.rx.load(Ordering::Relaxed),
        uptime_secs: status.connected_at.elapsed().as_secs(),
    }
}

struct Inner {
    state: EngineState,
    status: Option<MeshStatus>,
    shutdown: Arc<AtomicBool>,
}

/// The one place a tunnel is brought up or torn down. The daemon, the headless
/// CLI and an in-process GUI all drive this same object.
pub struct Engine {
    inner: Mutex<Inner>,
}

impl Engine {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                state: EngineState::Idle,
                status: None,
                shutdown: Arc::new(AtomicBool::new(false)),
            }),
        })
    }

    pub fn connect(&self, config: MeshConfig) -> Result<Snapshot, String> {
        let shutdown = {
            let mut inner = self.inner.lock().unwrap();
            match inner.state {
                EngineState::Connected => return Ok(self.snapshot_of(&inner)),
                EngineState::Connecting => return Err("already connecting".into()),
                _ => {}
            }
            inner.state = EngineState::Connecting;
            inner.shutdown = Arc::new(AtomicBool::new(false));
            Arc::clone(&inner.shutdown)
        };
        let result = meshnet::connect(config, shutdown);
        let mut inner = self.inner.lock().unwrap();
        match result {
            Ok(status) => {
                inner.status = Some(status);
                inner.state = EngineState::Connected;
                Ok(self.snapshot_of(&inner))
            }
            Err(message) => {
                inner.status = None;
                inner.state = EngineState::Failed { message: message.clone() };
                Err(message)
            }
        }
    }

    pub fn disconnect(&self) -> Snapshot {
        let (status, shutdown) = {
            let mut inner = self.inner.lock().unwrap();
            inner.shutdown.store(true, Ordering::Relaxed);
            (inner.status.take(), Arc::clone(&inner.shutdown))
        };
        if let Some(status) = status {
            let deadline = Instant::now() + STOP_GRACE;
            while !status.stopped.load(Ordering::Relaxed) && Instant::now() < deadline {
                std::thread::sleep(STOP_POLL);
            }
            if status.exit_node.is_some() {
                crate::route::emergency_cleanup(&status.tun_name);
            }
        }
        let mut inner = self.inner.lock().unwrap();
        if Arc::ptr_eq(&inner.shutdown, &shutdown) {
            inner.state = EngineState::Idle;
        }
        self.snapshot_of(&inner)
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut inner = self.inner.lock().unwrap();
        let dropped = inner
            .status
            .as_ref()
            .is_some_and(|s| s.connection_dropped.swap(false, Ordering::Relaxed));
        if dropped {
            inner.status = None;
            inner.state = EngineState::Dropped;
        }
        self.snapshot_of(&inner)
    }

    pub fn leave(&self) -> Result<Snapshot, String> {
        self.disconnect();
        if let Some(identity) = meshapi::load_identity() {
            meshapi::leave(&identity.token, &identity.device_id)?;
        }
        meshapi::clear_identity();
        Ok(self.snapshot())
    }

    pub fn clear_identity(&self) -> Snapshot {
        meshapi::clear_identity();
        self.snapshot()
    }

    pub fn advertise_exit(&self, enabled: bool) -> Result<Snapshot, String> {
        let identity = meshapi::load_identity().ok_or("not joined")?;
        let patch = meshapi::DevicePatch { exit_node: Some(enabled), ..meshapi::DevicePatch::default() };
        meshapi::update_device(&identity.token, &identity.device_id, &patch)?;
        Ok(self.snapshot())
    }

    fn snapshot_of(&self, inner: &Inner) -> Snapshot {
        Snapshot {
            version: env!("CARGO_PKG_VERSION").to_string(),
            state: inner.state.clone(),
            session: inner.status.as_ref().map(session_view),
            identity: meshapi::load_identity().map(redacted),
        }
    }
}

/// The GUI never needs the device credential itself; every call that does is
/// served here.
fn redacted(mut identity: MeshIdentity) -> MeshIdentity {
    identity.token.clear();
    identity.network.disco_secret.clear();
    identity
}
