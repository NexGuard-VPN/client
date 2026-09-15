#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshNetwork {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub cidr: String,
    #[serde(default)]
    pub dns_suffix: String,
    #[serde(default)]
    pub disco_secret: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshIdentity {
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub mesh_ip: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub network: MeshNetwork,
    #[serde(default)]
    pub relays: Vec<String>,
}

#[derive(Clone, serde::Deserialize)]
pub struct MeshSelf {
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mesh_ip: String,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub exit_node: bool,
}

#[derive(Clone, serde::Deserialize)]
pub struct MeshPeer {
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub mesh_ip: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub exit_node: bool,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub online: bool,
}

#[derive(Clone, serde::Deserialize)]
pub struct NetMap {
    #[serde(default)]
    pub version: u64,
    #[serde(rename = "self", default)]
    pub device: MeshSelf,
    #[serde(default)]
    pub network: MeshNetwork,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub peers: Vec<MeshPeer>,
}

#[derive(Clone, serde::Deserialize)]
pub struct Project {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub server_count: u32,
    #[serde(default)]
    pub device_count: u32,
    #[serde(default)]
    pub member_count: u32,
    #[serde(default)]
    pub network: Option<MeshNetwork>,
}

#[derive(Clone, serde::Deserialize)]
pub struct MeshNetworkSummary {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub cidr: String,
    #[serde(default)]
    pub dns_suffix: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub device_count: u32,
}

#[derive(Clone, serde::Deserialize)]
pub struct AcceptedInvite {
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub network: MeshNetwork,
    #[serde(default)]
    pub role: String,
}

#[derive(serde::Serialize)]
pub struct EnrollRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_token: Option<String>,
    pub name: String,
    pub public_key: String,
    pub os: String,
    pub os_version: String,
    pub client_version: String,
    pub advertise_exit_node: bool,
    pub advertise_routes: Vec<String>,
}

#[derive(Clone, serde::Deserialize)]
pub struct MeshDeviceView {
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub network_id: String,
    #[serde(default)]
    pub member_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mesh_ip: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub client_version: String,
    #[serde(default)]
    pub exit_node: bool,
    #[serde(default)]
    pub exit_node_approved: bool,
    #[serde(default)]
    pub advertised_routes: Vec<String>,
    #[serde(default)]
    pub approved_routes: Vec<String>,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub provisioned: bool,
    #[serde(default)]
    pub last_seen: i64,
}

#[derive(Clone, serde::Deserialize)]
pub struct MeshMember {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub max_devices: u32,
    #[serde(default)]
    pub device_count: u32,
}

#[derive(Clone, serde::Deserialize)]
pub struct MeshInvite {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub invite_url: String,
    #[serde(default)]
    pub expires_at: String,
}

#[derive(serde::Serialize)]
pub struct InviteRequest {
    pub email: String,
    pub role: String,
    pub max_devices: u32,
}

#[derive(serde::Serialize, Default)]
pub struct DevicePatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_node_approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_routes: Option<Vec<String>>,
}

impl Default for MeshSelf {
    fn default() -> Self {
        Self {
            device_id: String::new(),
            name: String::new(),
            mesh_ip: String::new(),
            routes: Vec::new(),
            exit_node: false,
        }
    }
}

impl Default for MeshNetwork {
    fn default() -> Self {
        Self {
            id: String::new(),
            project_id: String::new(),
            cidr: String::new(),
            dns_suffix: String::new(),
            disco_secret: String::new(),
        }
    }
}
