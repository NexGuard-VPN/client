use std::time::Duration;

use crate::meshtypes::{MeshConfig, MeshIdentity, MeshPeerView};

const QUICK_TIMEOUT: Duration = Duration::from_secs(5);
const LONG_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EngineState {
    Idle,
    Connecting,
    Connected,
    Dropped,
    Failed { message: String },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SessionView {
    pub device_id: String,
    pub name: String,
    pub address: String,
    pub network: String,
    pub dns_suffix: String,
    pub tun_name: String,
    pub exit_node: Option<String>,
    pub serving_exit: bool,
    pub advertising_exit: bool,
    pub relay_connected: bool,
    pub peers: Vec<MeshPeerView>,
    pub tx: u64,
    pub rx: u64,
    pub uptime_secs: u64,
}


#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub version: String,
    pub state: EngineState,
    pub session: Option<SessionView>,
    pub identity: Option<MeshIdentity>,
}

impl Snapshot {
    pub fn connected(&self) -> bool {
        self.state == EngineState::Connected
    }
}

#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    Connect { config: MeshConfig },
    Disconnect,
    Leave,
    ClearIdentity,
    AdvertiseExit { enabled: bool },
    ApplyUpdate { binary: String, signature: String },
    Restart,
}

impl Request {
    pub fn timeout(&self) -> Duration {
        match self {
            Request::Connect { .. } | Request::ApplyUpdate { .. } | Request::Leave => LONG_TIMEOUT,
            _ => QUICK_TIMEOUT,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub snapshot: Option<Snapshot>,
}

impl Response {
    pub fn from(result: Result<Snapshot, String>) -> Self {
        match result {
            Ok(snapshot) => Self { ok: true, error: String::new(), snapshot: Some(snapshot) },
            Err(error) => Self { ok: false, error, snapshot: None },
        }
    }

    pub fn into_result(self) -> Result<Snapshot, String> {
        match (self.ok, self.snapshot) {
            (true, Some(snapshot)) => Ok(snapshot),
            (true, None) => Err("empty reply".into()),
            (false, _) => Err(self.error),
        }
    }
}

pub fn encode<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| format!("encode: {}", e))
}

pub fn decode<T: serde::de::DeserializeOwned>(line: &str) -> Result<T, String> {
    serde_json::from_str(line.trim()).map_err(|e| format!("decode: {}", e))
}

