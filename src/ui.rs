use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::meshapi::{MeshDeviceView, MeshIdentity, MeshMember, Project};
use crate::meshnet::{MeshConfig, MeshPeerView, MeshStatus, PeerPath};
use crate::profiles::AppSettings;

#[derive(Clone, PartialEq)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Clone, Copy, PartialEq)]
enum View {
    SignIn,
    Home,
    NewProject,
    People,
    JoinInvite,
    AddDevice,
    Settings,
}

enum Action {
    Open(View),
    StartSignIn,
    CancelSignIn,
    Copy(String),
    OpenUrl(&'static str),
    Connect,
    Disconnect,
    SelectExit(Option<String>),
    ShareInternet(bool),
    SelectProject(String),
    CreateProject,
    AcceptInvite,
    CreateInvite,
    RemoveMember(String, String),
    ApproveDevice(String),
    ReloadProjects,
    ReloadTeam,
    ConfirmSignOut,
    ConfirmLeave,
    SignOut,
}

struct Remote<T> {
    slot: Arc<Mutex<Option<Result<T, String>>>>,
    loading: bool,
    value: Option<T>,
    error: Option<String>,
}

impl<T: Send + 'static> Remote<T> {
    fn new() -> Self {
        Self { slot: Arc::new(Mutex::new(None)), loading: false, value: None, error: None }
    }

    fn idle(&self) -> bool {
        !self.loading && self.value.is_none() && self.error.is_none()
    }

    fn start(&mut self, task: impl FnOnce() -> Result<T, String> + Send + 'static) {
        if self.loading {
            return;
        }
        self.loading = true;
        self.error = None;
        let slot = Arc::clone(&self.slot);
        std::thread::spawn(move || {
            *slot.lock().unwrap() = Some(task());
        });
    }

    fn poll(&mut self) -> bool {
        if !self.loading {
            return false;
        }
        let Some(result) = self.slot.lock().unwrap().take() else { return false };
        self.loading = false;
        match result {
            Ok(value) => {
                self.value = Some(value);
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
        true
    }

    fn reset(&mut self) {
        self.value = None;
        self.error = None;
    }
}

#[derive(Clone, Default)]
struct DeviceRow {
    device_id: String,
    name: String,
    ip: String,
    is_self: bool,
    provisioned: bool,
    shares_internet: bool,
    path: Option<PeerPath>,
    rtt_ms: Option<u32>,
    online: bool,
    last_seen: i64,
}

struct VpnApp {
    view: View,
    state: Arc<Mutex<ConnectionState>>,
    mesh_status: Arc<Mutex<Option<MeshStatus>>>,
    shutdown: Arc<AtomicBool>,
    connect_trigger: Arc<AtomicBool>,
    tray: Option<crate::tray::NexTray>,
    update_info: Arc<Mutex<Option<crate::api::UpdateInfo>>>,
    updating: Arc<AtomicBool>,
    update_result: Arc<Mutex<Option<Result<(), String>>>>,
    update_cancel: Arc<AtomicBool>,
    dl_progress: crate::modal::Progress,
    modal: Option<crate::modal::Modal>,
    error_modal_for: Option<String>,
    reconnect_pending: bool,
    quit_cleanup_done: bool,
    signed_in: bool,
    account: Option<String>,
    signin_in_progress: bool,
    signin_url: Arc<Mutex<Option<String>>>,
    signin_result: Arc<Mutex<Option<Result<(), String>>>>,
    signin_cancel: Arc<AtomicBool>,
    signin_error: Option<String>,
    signin_advanced: bool,
    projects: Remote<Vec<Project>>,
    project_id: Option<String>,
    project_task: Remote<Project>,
    project_name: String,
    members: Remote<Vec<MeshMember>>,
    devices: Remote<Vec<MeshDeviceView>>,
    invite: Remote<crate::meshapi::MeshInvite>,
    accept: Remote<crate::meshapi::AcceptedInvite>,
    team_task: Remote<()>,
    exit_geo: Remote<crate::api::GeoInfo>,
    invite_email: String,
    invite_role: String,
    invite_devices: u32,
    accept_token: String,
    mesh_identity: Option<MeshIdentity>,
    mesh_device_name: String,
    mesh_exit_node: Option<String>,
    mesh_network_id: Option<String>,
    share_internet: bool,
    settings_advertise_routes: String,
    settings_api_host: String,
    settings_magic_dns: bool,
    settings_start_login: bool,
    auto_reconnect: bool,
    saved_settings: AppSettings,
    copied: Option<(String, std::time::Instant)>,
    netmon: crate::netmon::NetMonitor,
    last_net_epoch: u64,
    connected_frame_since: Option<std::time::Instant>,
}

impl Default for VpnApp {
    fn default() -> Self {
        let update_info: Arc<Mutex<Option<crate::api::UpdateInfo>>> = Arc::new(Mutex::new(None));
        {
            let slot = Arc::clone(&update_info);
            std::thread::spawn(move || loop {
                if let Some(info) = crate::api::check_update() {
                    *slot.lock().unwrap() = Some(info);
                }
                std::thread::sleep(UPDATE_CHECK_INTERVAL);
            });
        }
        let settings = crate::profiles::load_settings();
        let signed_in = crate::api::load_account_token().is_some();
        Self {
            view: if signed_in { View::Home } else { View::SignIn },
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            mesh_status: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(AtomicBool::new(false)),
            connect_trigger: Arc::new(AtomicBool::new(false)),
            tray: None,
            update_info,
            updating: Arc::new(AtomicBool::new(false)),
            update_result: Arc::new(Mutex::new(None)),
            update_cancel: Arc::new(AtomicBool::new(false)),
            dl_progress: crate::modal::Progress::default(),
            modal: None,
            error_modal_for: None,
            reconnect_pending: false,
            quit_cleanup_done: false,
            signed_in,
            account: crate::api::account_email(),
            signin_in_progress: false,
            signin_url: Arc::new(Mutex::new(None)),
            signin_result: Arc::new(Mutex::new(None)),
            signin_cancel: Arc::new(AtomicBool::new(false)),
            signin_error: None,
            signin_advanced: false,
            projects: Remote::new(),
            project_id: optional(&settings.project_id),
            project_task: Remote::new(),
            project_name: String::new(),
            members: Remote::new(),
            devices: Remote::new(),
            invite: Remote::new(),
            accept: Remote::new(),
            team_task: Remote::new(),
            exit_geo: Remote::new(),
            invite_email: String::new(),
            invite_role: ROLE_MEMBER.to_string(),
            invite_devices: DEFAULT_INVITE_DEVICES,
            accept_token: String::new(),
            mesh_identity: crate::meshapi::load_identity(),
            mesh_device_name: crate::generate_client_name(),
            mesh_exit_node: optional(&settings.mesh_exit_node),
            mesh_network_id: optional(&settings.mesh_network_id),
            share_internet: settings.mesh_advertise_exit_node,
            settings_advertise_routes: settings.advertise_routes.clone(),
            settings_api_host: settings.api_host.clone(),
            settings_magic_dns: settings.mesh_magic_dns,
            settings_start_login: crate::autostart::is_enabled(),
            auto_reconnect: settings.auto_reconnect,
            saved_settings: settings,
            copied: None,
            netmon: crate::netmon::NetMonitor::start(),
            last_net_epoch: 0,
            connected_frame_since: None,
        }
    }
}

impl VpnApp {
    fn advertise_routes(&self) -> Vec<String> {
        self.settings_advertise_routes
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn connect(&mut self) {
        if !self.signed_in {
            self.view = View::SignIn;
            return;
        }
        if self.project_id.is_none() {
            self.view = View::Home;
            return;
        }
        if self.identity_is_foreign() {
            crate::meshapi::clear_identity();
            self.mesh_identity = None;
        }
        self.shutdown = Arc::new(AtomicBool::new(false));
        *self.state.lock().unwrap() = ConnectionState::Connecting;
        self.exit_geo.reset();
        let config = MeshConfig {
            network_id: self.mesh_network_id.clone(),
            project_id: self.project_id.clone(),
            device_name: self.mesh_device_name.clone(),
            exit_node: self.mesh_exit_node.clone(),
            advertise_exit_node: self.share_internet,
            manage_dns: self.settings_magic_dns,
            advertise_routes: self.advertise_routes(),
            ..MeshConfig::default()
        };
        let state = Arc::clone(&self.state);
        let slot = Arc::clone(&self.mesh_status);
        let shutdown = Arc::clone(&self.shutdown);
        std::thread::spawn(move || match crate::meshnet::connect(config, shutdown) {
            Ok(status) => {
                *slot.lock().unwrap() = Some(status);
                *state.lock().unwrap() = ConnectionState::Connected;
            }
            Err(e) => *state.lock().unwrap() = ConnectionState::Error(e),
        });
    }

    fn busy(&self) -> bool {
        matches!(
            *self.state.lock().unwrap(),
            ConnectionState::Connected | ConnectionState::Connecting
        )
    }

    fn reconnect(&mut self) {
        if self.busy() {
            self.disconnect();
            self.reconnect_pending = true;
        } else {
            self.connect();
        }
    }

    fn disconnect(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.exit_geo.reset();
        let mesh_slot = Arc::clone(&self.mesh_status);
        let state = Arc::clone(&self.state);
        *self.state.lock().unwrap() = ConnectionState::Connecting;
        std::thread::spawn(move || {
            std::thread::sleep(DISCONNECT_SETTLE);
            if let Some(mesh) = mesh_slot.lock().unwrap().take() {
                if mesh.exit_node.is_some() {
                    crate::route::emergency_cleanup(&mesh.tun_name);
                }
            }
            *state.lock().unwrap() = ConnectionState::Disconnected;
        });
    }

    fn handle_drop(&mut self) {
        if self.auto_reconnect && !self.shutdown.load(Ordering::Relaxed) {
            *self.state.lock().unwrap() = ConnectionState::Connecting;
            self.connect();
        } else {
            *self.state.lock().unwrap() = ConnectionState::Disconnected;
        }
    }

    fn current_settings(&self) -> AppSettings {
        AppSettings {
            advertise_routes: self.settings_advertise_routes.clone(),
            api_host: self.settings_api_host.trim().to_string(),
            auto_reconnect: self.auto_reconnect,
            mesh_exit_node: self.mesh_exit_node.clone().unwrap_or_default(),
            mesh_advertise_exit_node: self.share_internet,
            mesh_magic_dns: self.settings_magic_dns,
            mesh_network_id: self.mesh_network_id.clone().unwrap_or_default(),
            project_id: self.project_id.clone().unwrap_or_default(),
        }
    }

    fn persist_settings(&mut self) {
        let settings = self.current_settings();
        if settings != self.saved_settings {
            crate::profiles::save_settings(&settings);
            self.saved_settings = settings;
        }
    }

    fn publish_exit_advertisement(&self, enabled: bool) {
        let Some(identity) = self.mesh_identity.clone() else { return };
        std::thread::spawn(move || {
            let patch = crate::meshapi::DevicePatch {
                exit_node: Some(enabled),
                ..crate::meshapi::DevicePatch::default()
            };
            let _ = crate::meshapi::update_device(&identity.token, &identity.device_id, &patch);
        });
    }

    fn project_list(&self) -> &[Project] {
        self.projects.value.as_deref().unwrap_or_default()
    }

    fn current_project(&self) -> Option<&Project> {
        let id = self.project_id.as_deref()?;
        self.project_list().iter().find(|p| p.id == id)
    }

    fn project_network(&self) -> Option<&str> {
        self.current_project()?
            .network
            .as_ref()
            .map(|network| network.id.as_str())
            .filter(|id| !id.is_empty())
    }

    fn role(&self) -> &str {
        self.current_project().map_or(ROLE_MEMBER, |p| p.role.as_str())
    }

    fn is_admin(&self) -> bool {
        matches!(self.role(), ROLE_OWNER | ROLE_ADMIN)
    }

    fn pending_devices(&self) -> usize {
        self.devices
            .value
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|d| device_is_pending(d))
            .count()
    }

    fn self_device_id(&self) -> Option<String> {
        self.mesh_status
            .lock()
            .unwrap()
            .as_ref()
            .map(|status| status.device_id.clone())
            .or_else(|| self.mesh_identity.as_ref().map(|i| i.device_id.clone()))
            .filter(|id| !id.is_empty())
    }

    /// One roster for the whole screen. The control plane is the source of
    /// truth; the live session only adds how each device is reached.
    fn device_rows(&self) -> Vec<DeviceRow> {
        let live: Vec<MeshPeerView> = self
            .mesh_status
            .lock()
            .unwrap()
            .as_ref()
            .map(|status| status.peers.lock().map(|p| p.clone()).unwrap_or_default())
            .unwrap_or_default();
        let self_id = self.self_device_id().unwrap_or_default();
        let network = self.project_network().unwrap_or_default().to_string();

        let mut rows: Vec<DeviceRow> = match self.devices.value.as_ref() {
            Some(roster) => roster
                .iter()
                .filter(|device| {
                    network.is_empty()
                        || device.network_id.is_empty()
                        || device.network_id == network
                })
                .map(|device| {
                    let seen = live.iter().find(|p| p.device_id == device.device_id);
                    DeviceRow {
                        device_id: device.device_id.clone(),
                        name: device.name.clone(),
                        ip: device.mesh_ip.clone(),
                        is_self: !self_id.is_empty() && device.device_id == self_id,
                        provisioned: device.provisioned,
                        shares_internet: device.exit_node && device.exit_node_approved,
                        path: seen.map(|p| p.path),
                        rtt_ms: seen.and_then(|p| p.rtt_ms),
                        online: device.online || seen.is_some_and(|p| p.online),
                        last_seen: device.last_seen,
                    }
                })
                .collect(),
            None => live
                .iter()
                .map(|peer| DeviceRow {
                    device_id: peer.device_id.clone(),
                    name: peer.name.clone(),
                    ip: peer.ip.clone(),
                    is_self: false,
                    provisioned: false,
                    shares_internet: peer.exit_node,
                    path: Some(peer.path),
                    rtt_ms: peer.rtt_ms,
                    online: peer.online,
                    last_seen: 0,
                })
                .collect(),
        };

        if self.devices.value.is_none() {
            if let Some(status) = self.mesh_status.lock().unwrap().as_ref() {
                rows.push(DeviceRow {
                    device_id: status.device_id.clone(),
                    name: status.name.clone(),
                    ip: status.address.clone(),
                    is_self: true,
                    provisioned: false,
                    shares_internet: status.serving_exit,
                    path: None,
                    rtt_ms: None,
                    online: true,
                    last_seen: 0,
                });
            }
        }

        rows.sort_by(|a, b| b.is_self.cmp(&a.is_self).then_with(|| a.name.cmp(&b.name)));
        rows
    }

    fn ensure_loaded(&mut self) {
        if !self.signed_in {
            return;
        }
        if self.projects.idle() {
            self.projects.start(|| crate::meshapi::list_projects(&account_token()));
        }
        if self.project_id.is_none() {
            return;
        }
        if self.devices.idle() {
            self.devices.start(|| crate::meshapi::list_devices(&account_token()));
        }
        if self.members.idle() && self.is_admin() {
            self.members.start(|| crate::meshapi::list_members(&account_token()));
        }
        let routed = self.mesh_exit_node.is_some()
            && matches!(*self.state.lock().unwrap(), ConnectionState::Connected);
        if routed && self.exit_geo.idle() {
            self.exit_geo.start(crate::api::fetch_geo_self);
        }
    }

    fn poll_remotes(&mut self) {
        if self.projects.poll() {
            self.reconcile_projects();
        }
        self.members.poll();
        if self.devices.poll() {
            self.reconcile_exit_node();
        }
        self.exit_geo.poll();
        if self.project_task.poll() {
            if let Some(project) = self.project_task.value.take() {
                self.project_name.clear();
                self.project_id = Some(project.id);
                self.projects.reset();
                self.refresh_team();
                self.persist_settings();
                self.view = View::Home;
            }
        }
        if self.invite.poll() && self.invite.error.is_none() {
            self.invite_email.clear();
        }
        if self.team_task.poll() && self.team_task.error.is_none() {
            self.members.reset();
            self.devices.reset();
        }
        if self.accept.poll() {
            if let Some(accepted) = self.accept.value.take() {
                self.adopt_invite(accepted);
            }
        }
    }

    fn reconcile_projects(&mut self) {
        let Some(list) = self.projects.value.as_ref() else { return };
        let known = self
            .project_id
            .as_ref()
            .is_some_and(|id| list.iter().any(|p| &p.id == id));
        if !known {
            self.project_id = list.first().map(|p| p.id.clone());
        }
        self.persist_settings();
    }

    /// A device that stopped sharing its internet must not leave the picker
    /// naming it: "Direct" is then the truth.
    fn reconcile_exit_node(&mut self) {
        let Some(selected) = self.mesh_exit_node.clone() else { return };
        let rows = self.device_rows();
        if exit_candidates(&rows).iter().any(|row| row.device_id == selected) {
            return;
        }
        self.mesh_exit_node = None;
        self.exit_geo.reset();
        self.persist_settings();
        if self.busy() {
            self.reconnect();
        }
    }

    fn adopt_invite(&mut self, accepted: crate::meshapi::AcceptedInvite) {
        self.accept_token.clear();
        crate::meshapi::clear_identity();
        self.mesh_identity = None;
        self.mesh_network_id = optional(&accepted.network.id);
        if let Some(project_id) = optional(&accepted.project_id) {
            self.project_id = Some(project_id);
        }
        self.mesh_exit_node = None;
        self.projects.reset();
        self.refresh_team();
        self.persist_settings();
        self.view = View::Home;
    }

    fn identity_is_foreign(&self) -> bool {
        let Some(selected) = self.project_id.as_deref() else { return false };
        let Some(identity) = self.mesh_identity.as_ref() else { return false };
        match self.current_project() {
            Some(project) => !identity_serves(identity, project),
            None => identity_project(identity).is_some_and(|id| id != selected),
        }
    }

    fn refresh_team(&mut self) {
        self.members.reset();
        self.devices.reset();
        self.invite.reset();
        self.team_task.reset();
    }

    fn select_project(&mut self, id: String) {
        if self.project_id.as_deref() == Some(id.as_str()) {
            return;
        }
        self.project_id = Some(id);
        self.mesh_network_id = None;
        self.mesh_exit_node = None;
        self.refresh_team();
        self.persist_settings();
        if self.busy() {
            self.reconnect();
        }
    }

    fn approve_device(&mut self, device_id: String) {
        let Some(device) = self
            .devices
            .value
            .as_ref()
            .and_then(|list| list.iter().find(|d| d.device_id == device_id))
        else {
            return;
        };
        let exit_node_approved = if device.exit_node && !device.exit_node_approved {
            Some(true)
        } else {
            None
        };
        let pending = pending_routes(device);
        let approved_routes = if pending.is_empty() {
            None
        } else {
            let mut routes = device.approved_routes.clone();
            routes.extend(pending);
            Some(routes)
        };
        if exit_node_approved.is_none() && approved_routes.is_none() {
            return;
        }
        let patch = crate::meshapi::DevicePatch {
            exit_node_approved,
            approved_routes,
            ..crate::meshapi::DevicePatch::default()
        };
        self.team_task
            .start(move || crate::meshapi::update_device(&account_token(), &device_id, &patch));
    }

    fn leave_project(&mut self) {
        if self.busy() {
            self.reconnect_pending = false;
            self.disconnect();
        }
        self.mesh_exit_node = None;
        self.mesh_network_id = None;
        self.share_internet = false;
        self.persist_settings();
        self.devices.reset();
        let identity = self.mesh_identity.take();
        std::thread::spawn(move || {
            if let Some(identity) = identity {
                let _ = crate::meshapi::leave(&identity.token, &identity.device_id);
            }
            crate::meshapi::clear_identity();
        });
    }

    fn refresh_account(&mut self) {
        self.account = crate::api::account_email();
        self.signed_in = crate::api::load_account_token().is_some();
    }

    fn sign_out(&mut self) {
        self.reconnect_pending = false;
        if self.busy() {
            self.disconnect();
        }
        crate::api::clear_account_token();
        self.refresh_account();
        self.projects.reset();
        self.project_task.reset();
        self.refresh_team();
        self.accept.reset();
        self.signin_error = None;
        self.view = View::SignIn;
    }

    fn start_sign_in(&mut self) {
        if self.signin_in_progress {
            return;
        }
        self.persist_settings();
        self.signin_in_progress = true;
        self.signin_error = None;
        self.signin_cancel = Arc::new(AtomicBool::new(false));
        *self.signin_result.lock().unwrap() = None;
        *self.signin_url.lock().unwrap() = None;
        let result = Arc::clone(&self.signin_result);
        let url_slot = Arc::clone(&self.signin_url);
        let cancel = Arc::clone(&self.signin_cancel);
        std::thread::spawn(move || {
            let resp = match crate::api::request_account_login() {
                Ok(resp) => resp,
                Err(e) => {
                    *result.lock().unwrap() = Some(Err(e));
                    return;
                }
            };
            *url_slot.lock().unwrap() = Some(resp.login_url.clone());
            let _ = open::that(&resp.login_url);
            for _ in 0..SIGNIN_POLLS {
                std::thread::sleep(SIGNIN_INTERVAL);
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                match crate::api::poll_account_login(&resp.token) {
                    Ok(Some(_)) => {
                        *result.lock().unwrap() = Some(Ok(()));
                        return;
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        *result.lock().unwrap() = Some(Err(e));
                        return;
                    }
                }
            }
            *result.lock().unwrap() = Some(Err(ERR_SIGNIN_TIMEOUT.to_string()));
        });
    }

    fn cancel_sign_in(&mut self) {
        self.signin_cancel.store(true, Ordering::Relaxed);
        self.signin_in_progress = false;
        *self.signin_url.lock().unwrap() = None;
    }

    fn poll_sign_in(&mut self) {
        if !self.signin_in_progress {
            return;
        }
        let Some(result) = self.signin_result.lock().unwrap().take() else { return };
        self.signin_in_progress = false;
        match result {
            Ok(()) => {
                self.refresh_account();
                self.signin_error = None;
                self.projects.reset();
                self.refresh_team();
                self.view = View::Home;
            }
            Err(e) => self.signin_error = Some(explain(&e, ERR_NO_SIGNIN)),
        }
    }

    fn quit_cleanup(&mut self) {
        if self.quit_cleanup_done {
            return;
        }
        self.quit_cleanup_done = true;
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(mesh) = self.mesh_status.lock().unwrap().take() {
            if mesh.exit_node.is_some() {
                crate::route::emergency_cleanup(&mesh.tun_name);
            }
        }
        #[cfg(unix)]
        if let Some(dir) = crate::profiles::config_dir() {
            let _ = std::fs::remove_file(dir.join(GUI_SOCK));
        }
    }

    fn copy(&mut self, text: String) {
        let Ok(mut clipboard) = arboard::Clipboard::new() else { return };
        if clipboard.set_text(text.clone()).is_ok() {
            self.copied = Some((text, std::time::Instant::now()));
        }
    }

    fn is_copied(&self, text: &str) -> bool {
        self.copied
            .as_ref()
            .is_some_and(|(value, at)| value == text && at.elapsed() < COPY_FEEDBACK)
    }

    fn start_update(&mut self, url: String) {
        use crate::modal::{ButtonStyle, Modal, ModalAction, ModalButton};
        if self.updating.load(Ordering::Relaxed) {
            return;
        }
        self.updating.store(true, Ordering::Relaxed);
        self.update_cancel.store(false, Ordering::Relaxed);
        self.dl_progress.done.store(0, Ordering::Relaxed);
        self.dl_progress.total.store(0, Ordering::Relaxed);
        let version = self
            .update_info
            .lock()
            .unwrap()
            .as_ref()
            .map(|i| i.version.clone())
            .unwrap_or_default();
        self.modal = Some(Modal::progress(
            UPDATE_TITLE,
            &format!("{} v{}...", UPDATE_DOWNLOADING, version),
            self.dl_progress.clone(),
            vec![ModalButton::new(ACTION_CANCEL, ButtonStyle::Ghost, ModalAction::CancelUpdate)],
        ));
        let updating = Arc::clone(&self.updating);
        let result = Arc::clone(&self.update_result);
        let done = Arc::clone(&self.dl_progress.done);
        let total = Arc::clone(&self.dl_progress.total);
        let cancel = Arc::clone(&self.update_cancel);
        std::thread::spawn(move || {
            let progress = move |d: u64, t: u64| {
                done.store(d, Ordering::Relaxed);
                total.store(t, Ordering::Relaxed);
            };
            let r = crate::api::self_update(&url, &progress, &cancel);
            *result.lock().unwrap() = Some(r);
            updating.store(false, Ordering::Relaxed);
        });
    }

    fn poll_update_result(&mut self) {
        use crate::modal::{ButtonStyle, Modal, ModalAction, ModalButton};
        let Some(r) = self.update_result.lock().unwrap().take() else { return };
        let info = self.update_info.lock().unwrap().clone();
        let version = info.as_ref().map(|i| i.version.clone()).unwrap_or_default();
        self.modal = match r {
            Ok(()) => Some(Modal::success(
                UPDATE_READY_TITLE,
                &format!("{} v{} {}", APP_NAME, version, UPDATE_READY_BODY),
                vec![
                    ModalButton::new(ACTION_LATER, ButtonStyle::Ghost, ModalAction::Dismiss),
                    ModalButton::new(ACTION_RESTART, ButtonStyle::Primary, ModalAction::RestartApp),
                ],
            )),
            Err(ref e) if e.contains(CANCELLED_MARKER) => None,
            Err(e) => {
                let retry = info.map(|i| i.download_url).unwrap_or_default();
                Some(Modal::error(
                    UPDATE_FAILED_TITLE,
                    &explain(&e, ERR_NO_UPDATE),
                    vec![
                        ModalButton::new(ACTION_DISMISS, ButtonStyle::Ghost, ModalAction::Dismiss),
                        ModalButton::new(ACTION_RETRY, ButtonStyle::Primary, ModalAction::StartUpdate(retry)),
                    ],
                ))
            }
        };
    }

    fn handle_modal_action(&mut self, action: crate::modal::ModalAction) {
        use crate::modal::ModalAction::*;
        match action {
            Dismiss => {
                self.modal = None;
                self.error_modal_for = None;
                let mut st = self.state.lock().unwrap();
                if matches!(*st, ConnectionState::Error(_)) {
                    *st = ConnectionState::Disconnected;
                }
            }
            RetryConnect => {
                self.modal = None;
                self.error_modal_for = None;
                *self.state.lock().unwrap() = ConnectionState::Disconnected;
                self.connect();
            }
            StartUpdate(url) => {
                self.modal = None;
                self.start_update(url);
            }
            CancelUpdate => {
                self.update_cancel.store(true, Ordering::Relaxed);
                self.modal = None;
            }
            RestartApp => {
                if self.busy() {
                    self.disconnect();
                }
                crate::api::restart_self();
            }
            LeaveMesh => {
                self.modal = None;
                self.leave_project();
            }
            RevokeMember(id) => {
                self.modal = None;
                self.team_task
                    .start(move || crate::meshapi::revoke_member(&account_token(), &id));
            }
            SignOut => {
                self.modal = None;
                self.sign_out();
            }
        }
    }

    fn apply(&mut self, action: Action) {
        use crate::modal::{ButtonStyle, Modal, ModalAction, ModalButton};
        match action {
            Action::Open(view) => self.view = view,
            Action::StartSignIn => self.start_sign_in(),
            Action::CancelSignIn => self.cancel_sign_in(),
            Action::Copy(text) => self.copy(text),
            Action::OpenUrl(url) => {
                let _ = open::that(url);
            }
            Action::Connect => self.connect(),
            Action::Disconnect => {
                self.reconnect_pending = false;
                self.disconnect();
            }
            Action::SelectExit(device_id) => {
                if self.mesh_exit_node != device_id {
                    self.mesh_exit_node = device_id;
                    self.exit_geo.reset();
                    self.persist_settings();
                    if self.busy() {
                        self.reconnect();
                    }
                }
            }
            Action::ShareInternet(enabled) => {
                if self.share_internet != enabled {
                    self.share_internet = enabled;
                    self.persist_settings();
                    self.publish_exit_advertisement(enabled);
                    self.devices.reset();
                    if self.busy() {
                        self.reconnect();
                    }
                }
            }
            Action::SelectProject(id) => self.select_project(id),
            Action::CreateProject => {
                let name = self.project_name.trim().to_string();
                if name.is_empty() || self.project_task.loading {
                    return;
                }
                self.project_task.reset();
                self.project_task
                    .start(move || crate::meshapi::create_project(&account_token(), &name));
            }
            Action::AcceptInvite => {
                let token = self.accept_token.trim().to_string();
                if token.is_empty() || self.accept.loading {
                    return;
                }
                self.accept.reset();
                self.accept
                    .start(move || crate::meshapi::accept_invite(&account_token(), &token));
            }
            Action::CreateInvite => {
                let request = crate::meshapi::InviteRequest {
                    email: self.invite_email.trim().to_string(),
                    role: self.invite_role.clone(),
                    max_devices: self.invite_devices,
                };
                if request.email.is_empty() || self.invite.loading {
                    return;
                }
                self.invite.reset();
                self.invite
                    .start(move || crate::meshapi::create_invite(&account_token(), &request));
            }
            Action::RemoveMember(id, email) => {
                self.modal = Some(Modal::confirm(
                    MEMBER_REMOVE_TITLE,
                    &MEMBER_REMOVE_BODY.replace(PLACEHOLDER, &email),
                    vec![
                        ModalButton::new(ACTION_CANCEL, ButtonStyle::Ghost, ModalAction::Dismiss),
                        ModalButton::new(MEMBER_REMOVE, ButtonStyle::Danger, ModalAction::RevokeMember(id)),
                    ],
                ));
            }
            Action::ApproveDevice(device_id) => self.approve_device(device_id),
            Action::ReloadProjects => self.projects.reset(),
            Action::ReloadTeam => self.refresh_team(),
            Action::SignOut => self.sign_out(),
            Action::ConfirmSignOut => {
                self.modal = Some(Modal::confirm(
                    SIGN_OUT,
                    SIGN_OUT_BODY,
                    vec![
                        ModalButton::new(ACTION_CANCEL, ButtonStyle::Ghost, ModalAction::Dismiss),
                        ModalButton::new(SIGN_OUT, ButtonStyle::Danger, ModalAction::SignOut),
                    ],
                ));
            }
            Action::ConfirmLeave => {
                self.modal = Some(Modal::confirm(
                    LEAVE_PROJECT,
                    LEAVE_PROJECT_BODY,
                    vec![
                        ModalButton::new(ACTION_CANCEL, ButtonStyle::Ghost, ModalAction::Dismiss),
                        ModalButton::new(LEAVE_CONFIRM, ButtonStyle::Danger, ModalAction::LeaveMesh),
                    ],
                ));
            }
        }
    }
}

const APP_NAME: &str = "NexGuard";
const DOWNLOAD_URL: &str = "https://nexguard.sh/download";
const HEADLESS_COMMAND: &str = "nexguard --login && nexguard --mesh --share-internet";
const HTTP_MARKER: &str = "HTTP ";
const PLACEHOLDER: &str = "{}";
const CANCELLED_MARKER: &str = "cancelled";
const SEPARATOR: &str = " · ";
const CODE_PROJECT_REQUIRED: &str = "project_required";
const CODE_PROJECT_NOT_EMPTY: &str = "project_not_empty";
const TRANSPORT_PREFIXES: [&str; 6] =
    ["resolve ", "connect ", "tls ", "send:", "read:", "invalid host "];

const UPDATE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(4 * 3600);
const DISCONNECT_SETTLE: std::time::Duration = std::time::Duration::from_millis(200);
const COPY_FEEDBACK: std::time::Duration = std::time::Duration::from_secs(2);
const SIGNIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
const SIGNIN_POLLS: u32 = 300;
const BUSY_REPAINT: std::time::Duration = std::time::Duration::from_millis(200);
const IDLE_REPAINT: std::time::Duration = std::time::Duration::from_millis(500);
const ROAM_GRACE: u64 = 6;
const WINDOW_SIZE: [f32; 2] = [430.0, 640.0];
const WINDOW_MIN: [f32; 2] = [400.0, 560.0];

const ACTION_DISMISS: &str = "Dismiss";
const ACTION_RETRY: &str = "Try again";
const ACTION_CANCEL: &str = "Cancel";
const ACTION_LATER: &str = "Later";
const ACTION_RESTART: &str = "Restart now";
const ACTION_BACK: &str = "< Back";
const ACTION_PASTE: &str = "Paste";
const ACTION_DISCONNECT: &str = "Disconnect";
const ACTION_CONNECT: &str = "Connect";
const ACTION_COPY_LINK: &str = "Copy link";
const ACTION_OPEN_BROWSER: &str = "Open browser";

const SIGNIN_TITLE: &str = "Sign in to continue";
const SIGNIN_BODY: &str = "Your projects and devices live in your NexGuard account.";
const SIGNIN_BUTTON: &str = "Sign in";
const SIGNIN_WAITING: &str = "Waiting for your browser...";
const SIGNIN_HINT: &str = "Finish signing in the browser window that just opened.";
const SIGNIN_LINK_LABEL: &str = "Browser did not open? Use this link:";
const SIGNIN_ADVANCED: &str = "Control plane";
const SIGNIN_ADVANCED_HINT: &str = "Leave empty to use NexGuard's own service.";

const ERR_SIGNIN_TIMEOUT: &str = "The sign-in link expired. Try again.";
const ERR_NO_SIGNIN: &str =
    "This control plane does not offer browser sign-in. Check the address below.";
const ERR_NO_MESH: &str =
    "This control plane does not support device networks. Check the control plane address in Settings.";
const ERR_NO_UPDATE: &str = "No update is published for this build yet.";
const ERR_EXPIRED: &str = "Your session has expired. Sign in again.";
const ERR_PLAN: &str = "Your plan does not include this.";
const ERR_PROJECT_REQUIRED: &str = "Choose a project first.";
const ERR_PROJECT_NOT_EMPTY: &str = "That project still has devices in it.";
const ERR_SERVICE: &str = "The service is having trouble. Try again in a moment.";
const ERR_OFFLINE: &str = "Could not reach the control plane. Check your connection.";
const ERR_GENERIC: &str = "Something went wrong. Try again.";
const CONNECT_FAILED: &str = "Could not connect";

const PROJECTS_LOADING: &str = "Loading your projects...";
const PROJECT_EMPTY_TITLE: &str = "No projects yet";
const PROJECT_EMPTY_BODY: &str =
    "A project is a private network: your devices and the people you share them with.";
const PROJECT_CREATE: &str = "Create project";
const PROJECT_CREATING: &str = "Creating...";
const PROJECT_NAME_LABEL: &str = "Project name";
const PROJECT_NAME_HINT: &str = "e.g. Home";
const PROJECT_NEW_TITLE: &str = "New project";
const PROJECT_JOIN: &str = "Join with an invite";
const PROJECT_PEOPLE: &str = "People";
const PROJECT_SLUG_TIP: &str = "project name used in device DNS names";
const WORD_SERVER: &str = "server";
const WORD_SERVERS: &str = "servers";
const WORD_DEVICE: &str = "device";
const WORD_DEVICES: &str = "devices";
const WORD_PERSON: &str = "person";
const WORD_PEOPLE: &str = "people";

const THIS_DEVICE: &str = "This device";
const THIS_DEVICE_TAG: &str = "this device";
const STATUS_CONNECTED: &str = "Connected";
const STATUS_CONNECTING: &str = "Connecting...";
const STATUS_DISCONNECTING: &str = "Disconnecting...";
const STATUS_IDLE: &str = "Not connected";
const RELAY_DOWN: &str = "Relay offline";
const RELAY_DOWN_TIP: &str = "only devices reachable peer-to-peer are up right now";
const COPY_IP_TIP: &str = "click to copy this address";
const COPY_DONE: &str = "Copied ✓";
const MS_SUFFIX: &str = "ms";

const EXIT_LABEL: &str = "Internet";
const EXIT_DIRECT: &str = "Direct";
const EXIT_DIRECT_HINT: &str = "This device reaches the internet on its own.";
const EXIT_ROUTED_HINT: &str = "All internet traffic goes through {}.";
const EXIT_NONE_HINT: &str = "Turn on internet sharing on another device to route through it.";
const EXIT_FROM: &str = "Seen from";
const SHARE_INTERNET: &str = "Share this device's internet";
const SHARE_INTERNET_TIP: &str =
    "let the other devices in this project route their internet traffic through this one";
const SHARE_UNSUPPORTED: &str = "Sharing is not available on this platform yet.";
const MEMBER_EXIT_NOTE: &str = "An admin approves sharing before anyone can pick this device.";

const SECTION_DEVICES: &str = "Devices";
const DEVICES_EMPTY: &str = "Only this device so far.";
const DEVICES_LOADING: &str = "Loading devices...";
const DEVICE_ADD: &str = "+ Add a device";
const TAG_PROVISIONED: &str = "provisioned";
const TAG_SHARES: &str = "shares internet";
const PATH_DIRECT: &str = "direct";
const PATH_RELAY: &str = "relay";
const PATH_OFFLINE: &str = "offline";
const PENDING_ONE: &str = "device is waiting for your approval";
const PENDING_MANY: &str = "devices are waiting for your approval";
const PENDING_REVIEW: &str = "Review";

const ADD_TITLE: &str = "Add a device";
const ADD_OWN_LABEL: &str = "On your own machine";
const ADD_OWN_BODY: &str =
    "Install NexGuard there and sign in with this account. It joins this project by itself.";
const ADD_SERVER_LABEL: &str = "On a server, with no screen";
const ADD_SERVER_BODY: &str = "Install the same build, then run:";
const ADD_RENT_LABEL: &str = "Or rent one from us";
const ADD_RENT_ACTION: &str = "Provision a machine";
const ADD_RENT_DISABLED: &str =
    "Renting is paused until provisioned machines join projects as ordinary devices.";

const PEOPLE_TITLE: &str = "People";
const TEAM_LOADING: &str = "Loading...";
const TEAM_EMPTY: &str = "No teammates yet. Invite someone to share this project.";
const TEAM_ACTION_FAILED: &str = "That change did not go through.";
const TEAM_MEMBERS: &str = "Members";
const INVITE_SECTION: &str = "Invite someone";
const INVITE_EMAIL_HINT: &str = "teammate@example.com";
const INVITE_ROLE_LABEL: &str = "Role";
const INVITE_DEVICES_LABEL: &str = "Device limit";
const INVITE_SEND: &str = "Send invite";
const INVITE_SENT: &str = "Invited";
const INVITE_LINK_LABEL: &str = "Send this link to your teammate:";
const INVITE_EXPIRES: &str = "Expires";
const DEFAULT_INVITE_DEVICES: u32 = 3;
const MIN_INVITE_DEVICES: u32 = 1;
const MAX_INVITE_DEVICES: u32 = 25;
const MEMBER_DEVICES: &str = "devices";
const MEMBER_REMOVE: &str = "Remove";
const MEMBER_REMOVE_TITLE: &str = "Remove member";
const MEMBER_REMOVE_BODY: &str = "Removing {} also removes every device they joined to this project.";
const MEMBER_PENDING: &str = "pending";
const PENDING_SECTION: &str = "Waiting for approval";
const PENDING_HINT: &str =
    "These devices advertise something the rest of the project cannot use until you approve it.";
const PENDING_EXIT: &str = "Internet sharing";
const PENDING_EXIT_TIP: &str =
    "this device offers to share its internet, but no one can select it until you approve";
const PENDING_ROUTES: &str = "Routes";
const PENDING_ROUTES_TIP: &str =
    "this device offers to reach these subnets, but the routes are not installed until you approve";
const PENDING_APPROVE: &str = "Approve";
const PENDING_COUNT_TIP: &str = "devices of this member are waiting for your approval";
const NEVER_SEEN: &str = "never seen";
const OWNER_SELF: &str = "you";
const MEMBER_UNKNOWN: &str = "unknown member";
const ROLE_OWNER: &str = "owner";
const ROLE_ADMIN: &str = "admin";
const ROLE_MEMBER: &str = "member";
const ROLE_OWNER_TIP: &str = "owns this project and the plan it bills to";
const ROLE_ADMIN_TIP: &str = "can invite teammates and approve their devices";
const ROLE_MEMBER_TIP: &str = "can join devices to this project";

const JOIN_TITLE: &str = "Join with an invite";
const JOIN_HINT: &str = "Paste the invite token from your email to join a teammate's project.";
const JOIN_TOKEN_HINT: &str = "Invite token";
const JOIN_ACTION: &str = "Join";

const SETTINGS_TITLE: &str = "Settings";
const SETTINGS_TIP: &str = "Settings";
const SETTINGS_GENERAL: &str = "General";
const SETTINGS_START_LOGIN: &str = "Start NexGuard at login";
const SETTINGS_AUTO_RECONNECT: &str = "Reconnect automatically after a drop";
const SETTINGS_ADVANCED: &str = "Advanced";
const SETTINGS_ROUTES_LABEL: &str = "Share these subnets (comma-separated CIDRs)";
const SETTINGS_ROUTES_HINT: &str = "e.g. 192.168.1.0/24, 10.0.0.0/8";
const SETTINGS_HOST_LABEL: &str = "Control plane host";
const SETTINGS_DEVICE_SECTION: &str = "This device";
const MAGIC_DNS: &str = "Resolve device names (changes system DNS)";
const MAGIC_DNS_TIP: &str =
    "Lets you reach devices by name. Takes over this machine's DNS, so leave it off if another mesh VPN such as Tailscale is running.";
const LEAVE_PROJECT: &str = "Leave the project";
const LEAVE_PROJECT_BODY: &str =
    "This device will be removed from the project and will lose its address.";
const LEAVE_CONFIRM: &str = "Leave";
const ACCOUNT_SECTION: &str = "Account";
const ACCOUNT_TIP: &str = "the account this app is signed in to";
const SIGN_OUT: &str = "Sign out";
const SIGN_OUT_BODY: &str =
    "NexGuard will disconnect and return to the sign-in screen. This device stays in its project.";

const UPDATE_TITLE: &str = "Updating NexGuard";
const UPDATE_DOWNLOADING: &str = "Downloading";
const UPDATE_READY_TITLE: &str = "Update ready";
const UPDATE_READY_BODY: &str = "is installed. Restart to apply it.";
const UPDATE_FAILED_TITLE: &str = "Update failed";
const UPDATE_AVAILABLE: &str = "available";
const UPDATE_ACTION: &str = "Update";

const BADGE_TINT: f32 = 0.18;
const AVATAR_SIZE: f32 = 20.0;
const AVATAR_TEXT: f32 = 11.0;
const LOGO_LARGE: f32 = 56.0;

static SHOW_REQUEST: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
const GUI_SOCK: &str = "gui.sock";

fn account_token() -> String {
    crate::api::load_account_token().unwrap_or_default()
}

fn optional(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value.trim().to_string())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{} {}", count, if count == 1 { one } else { many })
}

fn http_status(raw: &str) -> Option<u16> {
    let rest = raw.split(HTTP_MARKER).nth(1)?;
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

fn error_code(raw: &str) -> String {
    raw.find('{')
        .and_then(|i| serde_json::from_str::<serde_json::Value>(raw[i..].trim()).ok())
        .and_then(|v| {
            v.get("error")
                .or_else(|| v.get("status"))
                .and_then(|e| e.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

fn already_friendly(raw: &str) -> bool {
    raw.ends_with('.') && raw.chars().next().is_some_and(|c| c.is_uppercase())
}

fn explain(raw: &str, missing: &str) -> String {
    match (http_status(raw), error_code(raw).as_str()) {
        (Some(404), _) => missing.to_string(),
        (Some(401) | Some(403), _) => ERR_EXPIRED.to_string(),
        (Some(402), _) => ERR_PLAN.to_string(),
        (Some(409), CODE_PROJECT_REQUIRED) => ERR_PROJECT_REQUIRED.to_string(),
        (Some(409), CODE_PROJECT_NOT_EMPTY) => ERR_PROJECT_NOT_EMPTY.to_string(),
        (Some(status), _) if status >= 500 => ERR_SERVICE.to_string(),
        (Some(_), _) => ERR_GENERIC.to_string(),
        (None, CODE_PROJECT_REQUIRED) => ERR_PROJECT_REQUIRED.to_string(),
        (None, _) if already_friendly(raw) => raw.to_string(),
        (None, _) if TRANSPORT_PREFIXES.iter().any(|p| raw.starts_with(p)) => ERR_OFFLINE.to_string(),
        _ => ERR_GENERIC.to_string(),
    }
}

fn pending_routes(device: &MeshDeviceView) -> Vec<String> {
    device
        .advertised_routes
        .iter()
        .filter(|route| !device.approved_routes.contains(route))
        .cloned()
        .collect()
}

fn device_is_pending(device: &MeshDeviceView) -> bool {
    (device.exit_node && !device.exit_node_approved) || !pending_routes(device).is_empty()
}

fn device_details(device: &MeshDeviceView) -> String {
    let mut parts = vec![device.mesh_ip.clone()];
    let platform = format!("{} {}", device.os, device.client_version);
    let platform = platform.trim();
    if !platform.is_empty() {
        parts.push(platform.to_string());
    }
    if !device.online {
        parts.push(format!("{} {}", PATH_OFFLINE, fmt_since(device.last_seen)));
    }
    parts.join(SEPARATOR)
}

fn device_owner_label(device: &MeshDeviceView, members: &[MeshMember]) -> String {
    if device.member_id.is_empty() {
        return OWNER_SELF.to_string();
    }
    members
        .iter()
        .find(|member| member.id == device.member_id)
        .map(|member| member.email.clone())
        .unwrap_or_else(|| MEMBER_UNKNOWN.to_string())
}

fn exit_candidates(rows: &[DeviceRow]) -> Vec<&DeviceRow> {
    rows.iter().filter(|row| row.shares_internet && !row.is_self).collect()
}

fn exit_label(selected: Option<&str>, rows: &[DeviceRow]) -> String {
    selected
        .and_then(|id| exit_candidates(rows).into_iter().find(|row| row.device_id == id))
        .map(|row| row.name.clone())
        .unwrap_or_else(|| EXIT_DIRECT.to_string())
}

fn details_line(row: &DeviceRow) -> String {
    let mut parts: Vec<String> = Vec::new();
    if row.is_self {
        parts.push(THIS_DEVICE_TAG.to_string());
    } else {
        let path = match row.path {
            Some(PeerPath::Direct) => Some(PATH_DIRECT),
            Some(PeerPath::Relay) => Some(PATH_RELAY),
            Some(PeerPath::Offline) => Some(PATH_OFFLINE),
            None if !row.online => Some(PATH_OFFLINE),
            None => None,
        };
        if let Some(path) = path {
            parts.push(path.to_string());
        }
        if let Some(rtt) = row.rtt_ms {
            parts.push(format!("{}{}", rtt, MS_SUFFIX));
        }
    }
    if row.provisioned {
        parts.push(TAG_PROVISIONED.to_string());
    }
    if row.shares_internet {
        parts.push(TAG_SHARES.to_string());
    }
    parts.join(SEPARATOR)
}

fn identity_project(identity: &MeshIdentity) -> Option<&str> {
    Some(identity.network.project_id.as_str()).filter(|id| !id.is_empty())
}

fn identity_serves(identity: &MeshIdentity, project: &Project) -> bool {
    if identity_project(identity) == Some(project.id.as_str()) {
        return true;
    }
    project
        .network
        .as_ref()
        .is_some_and(|network| !network.id.is_empty() && network.id == identity.network.id)
}

fn read_clipboard() -> Option<String> {
    arboard::Clipboard::new().ok()?.get_text().ok()
}

#[cfg(unix)]
fn claim_single_instance() -> bool {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    let Some(dir) = crate::profiles::config_dir() else { return true };
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(GUI_SOCK);
    if let Ok(mut stream) = UnixStream::connect(&path) {
        let _ = stream.write_all(b"show");
        return false;
    }
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else { return true };
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
    }
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 16];
            let _ = stream.read(&mut buf);
            SHOW_REQUEST.store(true, Ordering::Relaxed);
        }
    });
    true
}

#[cfg(target_os = "macos")]
fn set_dock_visible(visible: bool) {
    use std::os::raw::{c_char, c_void};
    #[link(name = "objc")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend();
    }
    unsafe {
        let cls = objc_getClass(b"NSApplication\0".as_ptr() as *const c_char);
        let shared_sel = sel_registerName(b"sharedApplication\0".as_ptr() as *const c_char);
        let policy_sel = sel_registerName(b"setActivationPolicy:\0".as_ptr() as *const c_char);
        if cls.is_null() || shared_sel.is_null() || policy_sel.is_null() {
            return;
        }
        let send0: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let app = send0(cls, shared_sel);
        if app.is_null() {
            return;
        }
        let send1: extern "C" fn(*mut c_void, *mut c_void, i64) -> bool =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let _ = send1(app, policy_sel, if visible { 0 } else { 1 });
    }
}

#[cfg(not(target_os = "macos"))]
fn set_dock_visible(_visible: bool) {}

fn show_window(ctx: &egui::Context) {
    set_dock_visible(true);
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
}

pub fn run_gui() {
    #[cfg(unix)]
    if !claim_single_instance() {
        return;
    }
    let icon = generate_app_icon();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(WINDOW_SIZE)
            .with_min_inner_size(WINDOW_MIN)
            .with_maximize_button(false)
            .with_title(APP_NAME)
            .with_icon(std::sync::Arc::new(icon)),
        ..Default::default()
    };
    eframe::run_native(
        APP_NAME,
        options,
        Box::new(move |cc| {
            setup_style(&cc.egui_ctx);
            let mut app = VpnApp::default();

            let api_host = crate::api::api_host();
            std::thread::spawn(move || {
                use std::net::ToSocketAddrs;
                let target = if api_host.contains(':') {
                    api_host
                } else {
                    format!("{}:{}", api_host, HTTPS_PORT)
                };
                let _ = target.to_socket_addrs();
            });

            app.tray = crate::tray::NexTray::new(crate::tray::TrayChannels {
                mesh_status: Arc::clone(&app.mesh_status),
                connect_trigger: Arc::clone(&app.connect_trigger),
            });

            if app.signed_in && app.mesh_identity.is_some() && app.auto_reconnect {
                app.connect();
            }
            Ok(Box::new(app))
        }),
    )
    .ok();
}

const HTTPS_PORT: u16 = 443;

fn cr(r: u8) -> egui::CornerRadius {
    egui::CornerRadius::same(r)
}

pub(crate) struct Theme {
    pub(crate) bg: egui::Color32,
    pub(crate) surface: egui::Color32,
    pub(crate) surface_hover: egui::Color32,
    pub(crate) border: egui::Color32,
    pub(crate) border_active: egui::Color32,
    pub(crate) text: egui::Color32,
    pub(crate) text_secondary: egui::Color32,
    pub(crate) text_muted: egui::Color32,
    pub(crate) accent: egui::Color32,
    pub(crate) accent_ink: egui::Color32,
    pub(crate) success: egui::Color32,
    pub(crate) danger: egui::Color32,
    pub(crate) warning: egui::Color32,
    pub(crate) input_bg: egui::Color32,
}

fn dark_theme() -> Theme {
    Theme {
        bg: egui::Color32::from_rgb(19, 17, 8),
        surface: egui::Color32::from_rgb(27, 24, 16),
        surface_hover: egui::Color32::from_rgb(34, 30, 19),
        border: egui::Color32::from_rgb(46, 40, 28),
        border_active: egui::Color32::from_rgb(242, 172, 60),
        text: egui::Color32::from_rgb(234, 227, 210),
        text_secondary: egui::Color32::from_rgb(178, 170, 148),
        text_muted: egui::Color32::from_rgb(154, 145, 124),
        accent: egui::Color32::from_rgb(242, 172, 60),
        accent_ink: egui::Color32::from_rgb(26, 18, 4),
        success: egui::Color32::from_rgb(124, 201, 139),
        danger: egui::Color32::from_rgb(229, 83, 75),
        warning: egui::Color32::from_rgb(224, 177, 92),
        input_bg: egui::Color32::from_rgb(15, 13, 6),
    }
}

pub(crate) fn theme() -> &'static Theme {
    use std::sync::OnceLock;
    static T: OnceLock<Theme> = OnceLock::new();
    T.get_or_init(dark_theme)
}

fn setup_style(ctx: &egui::Context) {
    let t = theme();
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    style.spacing.text_edit_width = 400.0;
    style.spacing.interact_size.y = 28.0;
    style.visuals.window_corner_radius = cr(12);

    for w in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
    ] {
        w.corner_radius = cr(10);
    }

    style.visuals.widgets.inactive.bg_fill = t.input_bg;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, t.border);
    style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, t.text_secondary);
    style.visuals.widgets.hovered.bg_fill = t.surface_hover;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.5_f32, t.border_active);
    style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, t.text);
    style.visuals.widgets.active.bg_fill = t.surface_hover;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.5_f32, t.accent);
    style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, t.text);
    style.visuals.widgets.noninteractive.bg_fill = t.surface;
    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, t.text_secondary);
    style.visuals.extreme_bg_color = t.input_bg;
    style.visuals.panel_fill = t.bg;
    style.visuals.window_fill = t.bg;
    style.visuals.selection.bg_fill = t.accent.linear_multiply(0.3);
    style.visuals.selection.stroke = egui::Stroke::new(1.0_f32, t.accent);

    ctx.set_style(style);
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    let t = theme();
    egui::Frame::default()
        .fill(t.surface)
        .corner_radius(cr(12))
        .inner_margin(16.0)
        .stroke(egui::Stroke::new(1.0_f32, t.border))
        .show(ui, add);
}

fn lbl(text: &str) -> egui::RichText {
    egui::RichText::new(text).size(12.0).color(theme().text_muted)
}

fn title_text(text: &str, size: f32) -> egui::RichText {
    egui::RichText::new(text)
        .size(size)
        .strong()
        .family(egui::FontFamily::Monospace)
        .color(theme().text)
}

fn status_dot(ui: &mut egui::Ui, filled: bool, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    if filled {
        ui.painter().circle_filled(rect.center(), 4.5, color);
    } else {
        ui.painter()
            .circle_stroke(rect.center(), 4.5, egui::Stroke::new(1.5_f32, color));
    }
}

fn badge(ui: &mut egui::Ui, label: &str, color: egui::Color32, tip: &str) {
    egui::Frame::default()
        .fill(color.linear_multiply(BADGE_TINT))
        .corner_radius(cr(6))
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).size(10.0).strong().color(color));
        })
        .response
        .on_hover_text(tip);
}

fn avatar(ui: &mut egui::Ui, email: &str) -> egui::Response {
    let t = theme();
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(AVATAR_SIZE, AVATAR_SIZE), egui::Sense::click());
    ui.painter().circle_filled(rect.center(), AVATAR_SIZE / 2.0, t.accent);
    if let Some(initial) = email.chars().next() {
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            initial.to_uppercase().to_string(),
            egui::FontId::proportional(AVATAR_TEXT),
            t.accent_ink,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn role_badge(ui: &mut egui::Ui, role: &str) {
    let t = theme();
    let (color, tip) = match role {
        ROLE_OWNER => (t.accent, ROLE_OWNER_TIP),
        ROLE_ADMIN => (t.warning, ROLE_ADMIN_TIP),
        _ => (t.text_muted, ROLE_MEMBER_TIP),
    };
    badge(ui, role, color, tip);
}

fn primary_button(ui: &mut egui::Ui, label: &str, width: f32) -> egui::Response {
    let t = theme();
    ui.add(
        egui::Button::new(egui::RichText::new(label).size(13.0).strong().color(t.accent_ink))
            .fill(t.accent)
            .min_size(egui::vec2(width, 38.0)),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn ghost_button(ui: &mut egui::Ui, label: &str, color: egui::Color32, width: f32) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(label).size(12.0).color(color))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0_f32, color))
            .min_size(egui::vec2(width, 30.0)),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn quiet_button(ui: &mut egui::Ui, label: &str, color: egui::Color32) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(label).size(12.0).color(color))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::NONE),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn icon_button(ui: &mut egui::Ui, glyph: &str, tip: &str) -> bool {
    let t = theme();
    ui.add(
        egui::Button::new(egui::RichText::new(glyph).size(14.0).color(t.text_muted))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::NONE)
            .min_size(egui::vec2(26.0, 24.0)),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
    .on_hover_text(tip)
    .clicked()
}

fn section_header(ui: &mut egui::Ui, title: &str, trailing: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.label(title_text(title, 13.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), trailing);
    });
    ui.add_space(6.0);
}

fn back_bar(ui: &mut egui::Ui, title: &str) -> bool {
    let t = theme();
    ui.add_space(4.0);
    let back = ui.horizontal(|ui| {
        let clicked = quiet_button(ui, ACTION_BACK, t.text_secondary).clicked();
        ui.label(title_text(title, 14.0));
        clicked
    });
    ui.add_space(8.0);
    back.inner
}

fn notice(ui: &mut egui::Ui, message: &str, action: Option<&str>) -> bool {
    let t = theme();
    let mut clicked = false;
    ui.vertical_centered(|ui| {
        ui.add_space(24.0);
        ui.add(
            egui::Label::new(egui::RichText::new(message).size(12.0).color(t.text_secondary))
                .wrap(),
        );
        if let Some(label) = action {
            ui.add_space(10.0);
            clicked = ghost_button(ui, label, t.accent, 0.0).clicked();
        }
        ui.add_space(20.0);
    });
    clicked
}

fn centered_spinner(ui: &mut egui::Ui, message: &str) {
    let t = theme();
    ui.vertical_centered(|ui| {
        ui.add_space(24.0);
        ui.spinner();
        ui.add_space(6.0);
        ui.label(egui::RichText::new(message).size(12.0).color(t.text_muted));
        ui.add_space(20.0);
    });
}

fn link_box(ui: &mut egui::Ui, url: &str) {
    let t = theme();
    egui::Frame::default()
        .fill(t.input_bg)
        .corner_radius(cr(8))
        .inner_margin(8.0)
        .stroke(egui::Stroke::new(1.0_f32, t.border))
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(url).size(11.0).monospace().color(t.text_secondary),
                )
                .wrap()
                .selectable(true),
            );
        });
}

fn copy_row(ui: &mut egui::Ui, app: &VpnApp, value: &str, action: &mut Option<Action>) {
    let t = theme();
    let copied = app.is_copied(value);
    let (label, color) = if copied { (COPY_DONE, t.success) } else { (ACTION_COPY_LINK, t.text) };
    let btn = egui::Button::new(egui::RichText::new(label).size(12.0).color(color))
        .fill(t.surface_hover)
        .min_size(egui::vec2(100.0, 28.0));
    if ui.add(btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
        *action = Some(Action::Copy(value.to_string()));
    }
}

fn text_field(ui: &mut egui::Ui, value: &mut String, hint: &str) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(f32::INFINITY)
            .margin(egui::vec2(10.0, 10.0)),
    )
}

impl eframe::App for VpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut tray_disconnect = false;
        if let Some(ref mut tray) = self.tray {
            tray.tick();
            if tray.show_requested {
                tray.show_requested = false;
                show_window(ctx);
            }
            if tray.disconnect_requested {
                tray.disconnect_requested = false;
                tray_disconnect = true;
            }
        }
        if tray_disconnect {
            self.reconnect_pending = false;
            self.disconnect();
        }

        if SHOW_REQUEST.swap(false, Ordering::Relaxed) {
            show_window(ctx);
        }

        let quit = self.tray.as_ref().is_some_and(|t| t.quit_requested);
        if quit && !self.quit_cleanup_done {
            self.quit_cleanup();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        if ctx.input(|i| i.viewport().close_requested()) {
            if quit {
                return;
            }
            if self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                set_dock_visible(false);
            } else {
                self.quit_cleanup();
                return;
            }
        }

        if self.signed_in && self.view == View::SignIn {
            self.view = View::Home;
        }

        let state = self.state.lock().unwrap().clone();
        let mesh_status = self.mesh_status.lock().unwrap().clone();
        if mesh_status.is_some()
            && self.mesh_identity.is_none()
            && matches!(state, ConnectionState::Connected)
        {
            self.mesh_identity = crate::meshapi::load_identity();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                if self.signed_in {
                    draw_app_bar(ui, self);
                    draw_view(ui, self, &state);
                } else {
                    draw_sign_in(ui, self);
                }
                draw_update_banner(ui, self);
            });
        });

        if let ConnectionState::Error(ref msg) = state {
            if self.error_modal_for.as_deref() != Some(msg.as_str()) {
                use crate::modal::{ButtonStyle, Modal, ModalAction, ModalButton};
                self.modal = Some(Modal::error(
                    CONNECT_FAILED,
                    &explain(msg, ERR_NO_MESH),
                    vec![
                        ModalButton::new(ACTION_DISMISS, ButtonStyle::Ghost, ModalAction::Dismiss),
                        ModalButton::new(ACTION_RETRY, ButtonStyle::Primary, ModalAction::RetryConnect),
                    ],
                ));
                self.error_modal_for = Some(msg.clone());
            }
        }

        self.poll_update_result();
        self.poll_sign_in();
        self.poll_remotes();
        self.ensure_loaded();

        if let Some(action) = self.modal.as_ref().and_then(|m| m.draw(ctx)) {
            self.handle_modal_action(action);
        }

        if self.reconnect_pending
            && matches!(state, ConnectionState::Disconnected | ConnectionState::Error(_))
        {
            self.reconnect_pending = false;
            self.connect();
        }

        if self.connect_trigger.swap(false, Ordering::Relaxed) {
            if !self.signed_in {
                self.view = View::SignIn;
                show_window(ctx);
            } else {
                self.view = View::Home;
                self.connect();
            }
        }

        let now_connected = matches!(state, ConnectionState::Connected);
        if now_connected {
            if self.connected_frame_since.is_none() {
                self.connected_frame_since = Some(std::time::Instant::now());
            }
        } else {
            self.connected_frame_since = None;
        }

        let net_epoch = self.netmon.epoch();
        if net_epoch != self.last_net_epoch {
            self.last_net_epoch = net_epoch;
            let grace_over = self
                .connected_frame_since
                .is_some_and(|t| t.elapsed().as_secs() >= ROAM_GRACE);
            if now_connected && grace_over && self.auto_reconnect {
                self.reconnect_pending = true;
                self.disconnect();
            }
        }

        if let Some(ref st) = mesh_status {
            if st.connection_dropped.swap(false, Ordering::Relaxed) {
                let _ = self.mesh_status.lock().unwrap().take();
                self.handle_drop();
            }
        }

        let repaint = if matches!(state, ConnectionState::Connected | ConnectionState::Connecting)
            || self.signin_in_progress
        {
            BUSY_REPAINT
        } else {
            IDLE_REPAINT
        };
        ctx.request_repaint_after(repaint);
    }
}

const MENU_WIDTH: f32 = 196.0;
const SELECTED_MARK: &str = "●";
const GEAR: &str = "⚙";
const CARET_SIZE: f32 = 12.0;

fn version_text() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

fn caret(ui: &mut egui::Ui, color: egui::Color32, up: bool) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(CARET_SIZE, CARET_SIZE), egui::Sense::click());
    let c = rect.center();
    let dy = if up { -1.0 } else { 1.0 };
    let points = vec![
        egui::pos2(c.x - 4.0, c.y - 2.0 * dy),
        egui::pos2(c.x + 4.0, c.y - 2.0 * dy),
        egui::pos2(c.x, c.y + 3.0 * dy),
    ];
    ui.painter()
        .add(egui::Shape::convex_polygon(points, color, egui::Stroke::NONE));
    response.on_hover_cursor(egui::CursorIcon::PointingHand).clicked()
}

fn menu_item(ui: &mut egui::Ui, label: &str, color: egui::Color32) -> bool {
    ui.add(
        egui::Button::new(egui::RichText::new(label).size(12.0).color(color))
            .fill(egui::Color32::TRANSPARENT)
            .min_size(egui::vec2(MENU_WIDTH, 26.0)),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
    .clicked()
}

fn draw_app_bar(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    let mut action: Option<Action> = None;
    let email = app.account.clone().unwrap_or_default();
    let popup_id = egui::Id::new("account_menu");

    ui.add_space(10.0);
    ui.horizontal(|ui| {
        let picked = avatar(ui, &email).clicked();
        let resp = quiet_button(ui, &email, t.text_secondary).on_hover_text(ACCOUNT_TIP);
        let open = ui.memory(|m| m.is_popup_open(popup_id));
        if picked | resp.clicked() | caret(ui, t.text_muted, open) {
            ui.memory_mut(|m| m.toggle_popup(popup_id));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if icon_button(ui, GEAR, SETTINGS_TIP) {
                action = Some(Action::Open(View::Settings));
            }
        });
        egui::popup_below_widget(
            ui,
            popup_id,
            &resp,
            egui::PopupCloseBehavior::CloseOnClick,
            |ui| {
                ui.set_min_width(MENU_WIDTH);
                if menu_item(ui, SIGN_OUT, t.danger) {
                    action = Some(Action::ConfirmSignOut);
                }
            },
        );
    });
    ui.add_space(8.0);
    ui.separator();

    if let Some(action) = action {
        app.apply(action);
    }
}

fn draw_view(ui: &mut egui::Ui, app: &mut VpnApp, state: &ConnectionState) {
    match app.view {
        View::SignIn | View::Home => draw_home(ui, app, state),
        View::NewProject => draw_new_project(ui, app),
        View::People => draw_people(ui, app),
        View::JoinInvite => draw_join_invite(ui, app),
        View::AddDevice => draw_add_device(ui, app),
        View::Settings => draw_settings(ui, app),
    }
}

fn draw_sign_in(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    let mut action: Option<Action> = None;
    ui.add_space(18.0);
    ui.vertical_centered(|ui| {
        draw_logo(ui, LOGO_LARGE);
        ui.add_space(8.0);
        ui.label(title_text(APP_NAME, 22.0));
        ui.label(egui::RichText::new(version_text()).size(10.0).color(t.text_muted));
    });
    ui.add_space(18.0);

    if app.signin_in_progress {
        let url = app.signin_url.lock().unwrap().clone();
        card(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(6.0);
                ui.spinner();
                ui.add_space(8.0);
                ui.label(egui::RichText::new(SIGNIN_WAITING).size(14.0).color(t.text));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(SIGNIN_HINT).size(11.0).color(t.text_muted));
                ui.add_space(6.0);
            });
        });
        if let Some(url) = url {
            ui.add_space(8.0);
            card(ui, |ui| {
                ui.label(lbl(SIGNIN_LINK_LABEL));
                ui.add_space(4.0);
                link_box(ui, &url);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    copy_row(ui, app, &url, &mut action);
                    let open = egui::Button::new(
                        egui::RichText::new(ACTION_OPEN_BROWSER).size(12.0).strong().color(t.accent_ink),
                    )
                    .fill(t.accent)
                    .min_size(egui::vec2(120.0, 28.0));
                    if ui.add(open).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        let _ = open::that(&url);
                    }
                });
            });
        }
        ui.add_space(12.0);
        ui.vertical_centered(|ui| {
            if ghost_button(ui, ACTION_CANCEL, t.text_secondary, 120.0).clicked() {
                action = Some(Action::CancelSignIn);
            }
        });
    } else {
        let error = app.signin_error.clone();
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new(SIGNIN_TITLE).size(16.0).strong().color(t.text));
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(egui::RichText::new(SIGNIN_BODY).size(12.0).color(t.text_muted))
                    .wrap(),
            );
            ui.add_space(16.0);
            if let Some(ref message) = error {
                ui.add(
                    egui::Label::new(egui::RichText::new(message).size(11.0).color(t.danger)).wrap(),
                );
                ui.add_space(10.0);
            }
            let label = if error.is_some() { ACTION_RETRY } else { SIGNIN_BUTTON };
            if primary_button(ui, label, 220.0).clicked() {
                action = Some(Action::StartSignIn);
            }
        });

        ui.add_space(16.0);
        let expanded = app.signin_advanced;
        let mut toggle = false;
        ui.vertical_centered(|ui| {
            ui.horizontal(|ui| {
                toggle |= quiet_button(ui, SIGNIN_ADVANCED, t.text_muted).clicked();
                toggle |= caret(ui, t.text_muted, expanded);
            });
        });
        if toggle {
            app.signin_advanced = !expanded;
        }
        if expanded {
            ui.add_space(4.0);
            card(ui, |ui| {
                text_field(ui, &mut app.settings_api_host, crate::api::DEFAULT_API_HOST);
                ui.add_space(4.0);
                ui.label(egui::RichText::new(SIGNIN_ADVANCED_HINT).size(10.0).color(t.text_muted));
            });
        }
    }

    if let Some(action) = action {
        app.apply(action);
    }
}

fn draw_home(ui: &mut egui::Ui, app: &mut VpnApp, state: &ConnectionState) {
    let t = theme();
    let mut action: Option<Action> = None;
    let projects = app.projects.value.clone();
    match projects {
        None => {
            if let Some(error) = app.projects.error.clone() {
                let message = explain(&error, ERR_NO_MESH);
                let expired = message == ERR_EXPIRED;
                let label = if expired { SIGNIN_BUTTON } else { ACTION_RETRY };
                if notice(ui, &message, Some(label)) {
                    action = Some(if expired { Action::SignOut } else { Action::ReloadProjects });
                }
            } else {
                centered_spinner(ui, PROJECTS_LOADING);
            }
        }
        Some(list) if list.is_empty() => {
            ui.add_space(24.0);
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(PROJECT_EMPTY_TITLE).size(16.0).strong().color(t.text));
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(PROJECT_EMPTY_BODY).size(12.0).color(t.text_muted),
                    )
                    .wrap(),
                );
                ui.add_space(20.0);
                if primary_button(ui, PROJECT_CREATE, 220.0).clicked() {
                    action = Some(Action::Open(View::NewProject));
                }
            });
        }
        Some(list) => {
            ui.add_space(8.0);
            draw_project_bar(ui, app, &list, &mut action);
            ui.add_space(14.0);
            let rows = app.device_rows();
            draw_this_device(ui, app, state, &rows, &mut action);
            ui.add_space(16.0);
            draw_devices(ui, app, &rows, &mut action);
            ui.add_space(10.0);
        }
    }
    if let Some(action) = action {
        app.apply(action);
    }
}

fn draw_project_bar(
    ui: &mut egui::Ui,
    app: &mut VpnApp,
    projects: &[Project],
    action: &mut Option<Action>,
) {
    let t = theme();
    let current = app.current_project().cloned().or_else(|| projects.first().cloned());
    let Some(current) = current else { return };
    let admin = app.is_admin();
    let popup_id = egui::Id::new("project_switcher");

    ui.horizontal(|ui| {
        let btn = egui::Button::new(
            egui::RichText::new(&current.name).size(13.0).strong().color(t.text),
        )
        .fill(t.surface)
        .stroke(egui::Stroke::new(1.0_f32, t.border))
        .min_size(egui::vec2(0.0, 30.0));
        let mut resp = ui.add(btn).on_hover_cursor(egui::CursorIcon::PointingHand);
        if !current.slug.is_empty() {
            resp = resp.on_hover_text(format!("{} — {}", current.slug, PROJECT_SLUG_TIP));
        }
        let open = ui.memory(|m| m.is_popup_open(popup_id));
        if resp.clicked() | caret(ui, t.text_muted, open) {
            ui.memory_mut(|m| m.toggle_popup(popup_id));
        }
        role_badge(ui, &current.role);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let mut counts = Vec::new();
            if current.server_count > 0 {
                counts.push(plural(current.server_count as usize, WORD_SERVER, WORD_SERVERS));
            }
            counts.push(plural(current.device_count as usize, WORD_DEVICE, WORD_DEVICES));
            counts.push(plural(current.member_count as usize, WORD_PERSON, WORD_PEOPLE));
            ui.label(
                egui::RichText::new(counts.join(SEPARATOR)).size(11.0).color(t.text_muted),
            );
        });
        egui::popup_below_widget(
            ui,
            popup_id,
            &resp,
            egui::PopupCloseBehavior::CloseOnClick,
            |ui| {
                ui.set_min_width(MENU_WIDTH);
                if projects.len() > 1 {
                    for project in projects {
                        let selected = project.id == current.id;
                        let label = if selected {
                            format!("{} {}", SELECTED_MARK, project.name)
                        } else {
                            project.name.clone()
                        };
                        let color = if selected { t.accent } else { t.text };
                        if menu_item(ui, &label, color) && !selected {
                            *action = Some(Action::SelectProject(project.id.clone()));
                        }
                    }
                    ui.separator();
                }
                if menu_item(ui, PROJECT_NEW_TITLE, t.text) {
                    *action = Some(Action::Open(View::NewProject));
                }
                if menu_item(ui, PROJECT_JOIN, t.text) {
                    *action = Some(Action::Open(View::JoinInvite));
                }
                if admin && menu_item(ui, PROJECT_PEOPLE, t.text) {
                    *action = Some(Action::Open(View::People));
                }
            },
        );
    });
}

fn draw_this_device(
    ui: &mut egui::Ui,
    app: &VpnApp,
    state: &ConnectionState,
    rows: &[DeviceRow],
    action: &mut Option<Action>,
) {
    let t = theme();
    let mesh = app.mesh_status.lock().unwrap().clone();
    let disconnecting = app.shutdown.load(Ordering::Relaxed);
    let address = mesh
        .as_ref()
        .map(|status| status.address.clone())
        .or_else(|| app.mesh_identity.as_ref().map(|i| i.mesh_ip.clone()))
        .unwrap_or_default();
    let relay_down = mesh
        .as_ref()
        .is_some_and(|status| !status.relay_connected.load(Ordering::Relaxed));
    let (status_label, status_color, status_filled) = match state {
        ConnectionState::Connected => (STATUS_CONNECTED, t.success, true),
        ConnectionState::Connecting if disconnecting => (STATUS_DISCONNECTING, t.warning, false),
        ConnectionState::Connecting => (STATUS_CONNECTING, t.warning, false),
        _ => (STATUS_IDLE, t.text_muted, false),
    };
    let connected = matches!(state, ConnectionState::Connected);
    let busy = matches!(state, ConnectionState::Connecting);
    let candidates = exit_candidates(rows);
    let selected = app.mesh_exit_node.clone();

    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(THIS_DEVICE).size(13.0).strong().color(t.text));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(egui::RichText::new(status_label).size(11.0).strong().color(status_color));
                status_dot(ui, status_filled, status_color);
                if relay_down {
                    badge(ui, RELAY_DOWN, t.warning, RELAY_DOWN_TIP);
                }
            });
        });
        if !address.is_empty() {
            ui.add_space(2.0);
            copyable_address(ui, app, &address, action);
        }

        ui.add_space(10.0);
        if busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(lbl(status_label));
            });
        } else if connected {
            if ghost_button(ui, ACTION_DISCONNECT, t.danger, 120.0).clicked() {
                *action = Some(Action::Disconnect);
            }
        } else if primary_button(ui, ACTION_CONNECT, 120.0).clicked() {
            *action = Some(Action::Connect);
        }

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.label(lbl(EXIT_LABEL));
            egui::ComboBox::from_id_salt("exit_node")
                .width(ui.available_width())
                .selected_text(
                    egui::RichText::new(exit_label(selected.as_deref(), rows))
                        .size(12.0)
                        .color(t.text),
                )
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_label(
                            selected.is_none(),
                            egui::RichText::new(EXIT_DIRECT).size(12.0),
                        )
                        .clicked()
                    {
                        *action = Some(Action::SelectExit(None));
                    }
                    for row in &candidates {
                        let picked = selected.as_deref() == Some(row.device_id.as_str());
                        if ui
                            .selectable_label(picked, egui::RichText::new(&row.name).size(12.0))
                            .clicked()
                        {
                            *action = Some(Action::SelectExit(Some(row.device_id.clone())));
                        }
                    }
                });
        });
        ui.add_space(4.0);
        let hint = match selected.as_deref() {
            Some(id) => EXIT_ROUTED_HINT.replace(PLACEHOLDER, &exit_label(Some(id), rows)),
            None if candidates.is_empty() => EXIT_NONE_HINT.to_string(),
            None => EXIT_DIRECT_HINT.to_string(),
        };
        ui.label(lbl(&hint));
        if let Some(geo) = app.exit_geo.value.as_ref().filter(|_| selected.is_some() && connected) {
            ui.label(lbl(&format!("{} {}", EXIT_FROM, geo_summary(geo))));
        }

        ui.add_space(10.0);
        let supported = crate::exitnode::ExitNodeState::is_supported();
        let mut sharing = app.share_internet;
        let resp = ui.add_enabled(supported, egui::Checkbox::new(&mut sharing, SHARE_INTERNET));
        if supported {
            if resp.on_hover_text(SHARE_INTERNET_TIP).changed() {
                *action = Some(Action::ShareInternet(sharing));
            }
            if app.share_internet && app.role() == ROLE_MEMBER {
                ui.label(lbl(MEMBER_EXIT_NOTE));
            }
        } else {
            ui.label(lbl(SHARE_UNSUPPORTED));
        }
    });
}

fn copyable_address(ui: &mut egui::Ui, app: &VpnApp, address: &str, action: &mut Option<Action>) {
    let t = theme();
    let copied = app.is_copied(address);
    let (text, color) = if copied { (COPY_DONE, t.success) } else { (address, t.text_secondary) };
    let resp = ui
        .add(
            egui::Label::new(egui::RichText::new(text).size(12.0).monospace().color(color))
                .sense(egui::Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(COPY_IP_TIP);
    if resp.clicked() {
        *action = Some(Action::Copy(address.to_string()));
    }
}

fn geo_summary(geo: &crate::api::GeoInfo) -> String {
    let place = if geo.city.is_empty() {
        geo.country.clone()
    } else {
        format!("{}, {}", geo.city, geo.country)
    };
    if place.is_empty() {
        geo.ip.clone()
    } else {
        format!("{}{}{}", geo.ip, SEPARATOR, place)
    }
}

fn draw_devices(
    ui: &mut egui::Ui,
    app: &VpnApp,
    rows: &[DeviceRow],
    action: &mut Option<Action>,
) {
    let t = theme();
    let pending = if app.is_admin() { app.pending_devices() } else { 0 };

    section_header(ui, SECTION_DEVICES, |_ui| {});

    if rows.is_empty() {
        if app.devices.loading {
            ui.label(lbl(DEVICES_LOADING));
        } else {
            ui.label(lbl(DEVICES_EMPTY));
        }
    }

    for row in rows {
        egui::Frame::default()
            .fill(t.surface)
            .corner_radius(cr(10))
            .inner_margin(12.0)
            .stroke(egui::Stroke::new(1.0_f32, if row.is_self { t.border_active } else { t.border }))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&row.name).size(13.0).strong().color(t.text));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if !row.is_self && !row.online {
                            ui.label(
                                egui::RichText::new(fmt_since(row.last_seen))
                                    .size(10.0)
                                    .color(t.text_muted),
                            );
                        }
                    });
                });
                ui.horizontal(|ui| {
                    if !row.ip.is_empty() {
                        copyable_address(ui, app, &row.ip, action);
                    }
                    let details = details_line(row);
                    if !details.is_empty() {
                        ui.label(
                            egui::RichText::new(format!("{}{}", SEPARATOR, details))
                                .size(11.0)
                                .color(t.text_muted),
                        );
                    }
                });
            });
        ui.add_space(3.0);
    }

    ui.add_space(4.0);
    if quiet_button(ui, DEVICE_ADD, t.accent).clicked() {
        *action = Some(Action::Open(View::AddDevice));
    }

    if pending > 0 {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(plural(pending, PENDING_ONE, PENDING_MANY))
                    .size(12.0)
                    .color(t.warning),
            );
            if quiet_button(ui, PENDING_REVIEW, t.accent).clicked() {
                *action = Some(Action::Open(View::People));
            }
        });
    }
}

fn draw_add_device(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    let mut action: Option<Action> = None;
    if back_bar(ui, ADD_TITLE) {
        action = Some(Action::Open(View::Home));
    }

    card(ui, |ui| {
        ui.label(egui::RichText::new(ADD_OWN_LABEL).size(12.0).strong().color(t.text));
        ui.add_space(4.0);
        ui.add(egui::Label::new(lbl(ADD_OWN_BODY)).wrap());
        ui.add_space(10.0);
        link_box(ui, DOWNLOAD_URL);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            copy_row(ui, app, DOWNLOAD_URL, &mut action);
            let open = egui::Button::new(
                egui::RichText::new(ACTION_OPEN_BROWSER).size(12.0).strong().color(t.accent_ink),
            )
            .fill(t.accent)
            .min_size(egui::vec2(120.0, 28.0));
            if ui.add(open).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                action = Some(Action::OpenUrl(DOWNLOAD_URL));
            }
        });
    });

    ui.add_space(10.0);
    card(ui, |ui| {
        ui.label(egui::RichText::new(ADD_SERVER_LABEL).size(12.0).strong().color(t.text));
        ui.add_space(4.0);
        ui.add(egui::Label::new(lbl(ADD_SERVER_BODY)).wrap());
        ui.add_space(8.0);
        link_box(ui, HEADLESS_COMMAND);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            copy_row(ui, app, HEADLESS_COMMAND, &mut action);
        });
    });

    ui.add_space(10.0);
    card(ui, |ui| {
        ui.label(egui::RichText::new(ADD_RENT_LABEL).size(12.0).strong().color(t.text));
        ui.add_space(8.0);
        ui.add_enabled(
            false,
            egui::Button::new(egui::RichText::new(ADD_RENT_ACTION).size(12.0).color(t.text_muted))
                .fill(egui::Color32::TRANSPARENT)
                .stroke(egui::Stroke::new(1.0_f32, t.border))
                .min_size(egui::vec2(190.0, 30.0)),
        );
        ui.add_space(6.0);
        ui.add(egui::Label::new(lbl(ADD_RENT_DISABLED)).wrap());
    });
    ui.add_space(10.0);

    if let Some(action) = action {
        app.apply(action);
    }
}

fn draw_new_project(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    let mut action: Option<Action> = None;
    if back_bar(ui, PROJECT_NEW_TITLE) {
        action = Some(Action::Open(View::Home));
    }
    let pending = app.project_task.loading;
    let error = app.project_task.error.clone();
    card(ui, |ui| {
        ui.add(
            egui::Label::new(egui::RichText::new(PROJECT_EMPTY_BODY).size(11.0).color(t.text_muted))
                .wrap(),
        );
        ui.add_space(12.0);
        ui.label(lbl(PROJECT_NAME_LABEL));
        text_field(ui, &mut app.project_name, PROJECT_NAME_HINT);
    });
    ui.add_space(12.0);
    ui.vertical_centered(|ui| {
        let ready = !app.project_name.trim().is_empty() && !pending;
        let label = if pending { PROJECT_CREATING } else { PROJECT_CREATE };
        let btn = egui::Button::new(
            egui::RichText::new(label).size(13.0).strong().color(t.accent_ink),
        )
        .fill(t.accent)
        .min_size(egui::vec2(220.0, 38.0));
        if ui.add_enabled(ready, btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            action = Some(Action::CreateProject);
        }
        if let Some(ref message) = error {
            ui.add_space(10.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(explain(message, ERR_NO_MESH)).size(11.0).color(t.danger),
                )
                .wrap(),
            );
        }
    });
    if let Some(action) = action {
        app.apply(action);
    }
}

fn draw_join_invite(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    let mut action: Option<Action> = None;
    if back_bar(ui, JOIN_TITLE) {
        action = Some(Action::Open(View::Home));
    }
    let pending = app.accept.loading;
    let error = app.accept.error.clone();
    card(ui, |ui| {
        ui.label(lbl(JOIN_HINT));
        ui.add_space(10.0);
        text_field(ui, &mut app.accept_token, JOIN_TOKEN_HINT);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let ready = !app.accept_token.trim().is_empty() && !pending;
            let btn = egui::Button::new(
                egui::RichText::new(JOIN_ACTION).size(12.0).strong().color(t.accent_ink),
            )
            .fill(t.accent)
            .min_size(egui::vec2(90.0, 30.0));
            if ui.add_enabled(ready, btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                action = Some(Action::AcceptInvite);
            }
            if ghost_button(ui, ACTION_PASTE, t.text_secondary, 80.0).clicked() {
                if let Some(text) = read_clipboard() {
                    app.accept_token = text.trim().to_owned();
                }
            }
            if pending {
                ui.spinner();
            }
        });
        if let Some(ref message) = error {
            ui.add_space(8.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(explain(message, ERR_NO_MESH)).size(11.0).color(t.danger),
                )
                .wrap(),
            );
        }
    });
    if let Some(action) = action {
        app.apply(action);
    }
}

fn draw_people(ui: &mut egui::Ui, app: &mut VpnApp) {
    let mut action: Option<Action> = None;
    if back_bar(ui, PEOPLE_TITLE) {
        action = Some(Action::Open(View::Home));
    }
    draw_pending_approvals(ui, app, &mut action);
    draw_members(ui, app, &mut action);
    draw_invite_form(ui, app, &mut action);
    if let Some(action) = action {
        app.apply(action);
    }
}

fn draw_pending_approvals(ui: &mut egui::Ui, app: &VpnApp, action: &mut Option<Action>) {
    let t = theme();
    let devices = app.devices.value.clone().unwrap_or_default();
    let members = app.members.value.clone().unwrap_or_default();
    let pending: Vec<&MeshDeviceView> = devices.iter().filter(|d| device_is_pending(d)).collect();
    if pending.is_empty() {
        return;
    }
    card(ui, |ui| {
        ui.label(egui::RichText::new(PENDING_SECTION).size(13.0).strong().color(t.warning));
        ui.add_space(4.0);
        ui.label(lbl(PENDING_HINT));
        ui.add_space(8.0);
        for device in pending {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&device.name).size(12.0).strong().color(t.text));
                        ui.label(
                            egui::RichText::new(device_owner_label(device, &members))
                                .size(11.0)
                                .color(t.text_secondary),
                        );
                    });
                    ui.label(egui::RichText::new(device_details(device)).size(10.0).color(t.text_muted));
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        if device.exit_node && !device.exit_node_approved {
                            badge(ui, PENDING_EXIT, t.warning, PENDING_EXIT_TIP);
                        }
                        let routes = pending_routes(device);
                        if !routes.is_empty() {
                            badge(ui, PENDING_ROUTES, t.warning, PENDING_ROUTES_TIP);
                            ui.label(
                                egui::RichText::new(routes.join(", "))
                                    .size(10.0)
                                    .monospace()
                                    .color(t.text_muted),
                            );
                        }
                    });
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let btn = egui::Button::new(
                        egui::RichText::new(PENDING_APPROVE).size(11.0).strong().color(t.accent_ink),
                    )
                    .fill(t.accent)
                    .min_size(egui::vec2(80.0, 26.0));
                    if ui.add(btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        *action = Some(Action::ApproveDevice(device.device_id.clone()));
                    }
                });
            });
            ui.add_space(6.0);
        }
    });
    ui.add_space(8.0);
}

fn draw_members(ui: &mut egui::Ui, app: &VpnApp, action: &mut Option<Action>) {
    let t = theme();
    let members = app.members.value.clone().unwrap_or_default();
    let devices = app.devices.value.clone().unwrap_or_default();
    let loading = app.members.loading;
    let load_error = app.members.error.clone();
    let task_error = app.team_task.error.clone();
    let task_pending = app.team_task.loading;

    card(ui, |ui| {
        ui.label(egui::RichText::new(TEAM_MEMBERS).size(13.0).strong().color(t.text));
        ui.add_space(8.0);
        if loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(lbl(TEAM_LOADING));
            });
        } else if let Some(message) = load_error {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(explain(&message, ERR_NO_MESH))
                        .size(11.0)
                        .color(t.text_secondary),
                )
                .wrap(),
            );
            ui.add_space(8.0);
            if ghost_button(ui, ACTION_RETRY, t.accent, 0.0).clicked() {
                *action = Some(Action::ReloadTeam);
            }
        } else if members.is_empty() {
            ui.label(lbl(TEAM_EMPTY));
        } else {
            for member in &members {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(&member.email).size(12.0).strong().color(t.text));
                        ui.label(
                            egui::RichText::new(format!(
                                "{} · {}/{} {}",
                                member.status, member.device_count, member.max_devices, MEMBER_DEVICES
                            ))
                            .size(10.0)
                            .color(t.text_muted),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if quiet_button(ui, MEMBER_REMOVE, t.danger).clicked() {
                            *action = Some(Action::RemoveMember(
                                member.id.clone(),
                                member.email.clone(),
                            ));
                        }
                        ui.add_space(6.0);
                        role_badge(ui, &member.role);
                        let waiting = devices
                            .iter()
                            .filter(|d| d.member_id == member.id && device_is_pending(d))
                            .count();
                        if waiting > 0 {
                            ui.add_space(6.0);
                            badge(
                                ui,
                                &format!("{} {}", waiting, MEMBER_PENDING),
                                t.warning,
                                PENDING_COUNT_TIP,
                            );
                        }
                    });
                });
                ui.add_space(6.0);
            }
        }
        if task_pending {
            ui.add_space(4.0);
            ui.spinner();
        }
        if let Some(message) = task_error {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(TEAM_ACTION_FAILED).size(11.0).strong().color(t.danger));
            ui.add(
                egui::Label::new(
                    egui::RichText::new(explain(&message, ERR_NO_MESH))
                        .size(11.0)
                        .color(t.text_secondary),
                )
                .wrap(),
            );
        }
    });
    ui.add_space(8.0);
}

fn draw_invite_form(ui: &mut egui::Ui, app: &mut VpnApp, action: &mut Option<Action>) {
    let t = theme();
    let invite = app.invite.value.clone();
    let invite_error = app.invite.error.clone();
    let pending = app.invite.loading;

    card(ui, |ui| {
        ui.label(egui::RichText::new(INVITE_SECTION).size(13.0).strong().color(t.text));
        ui.add_space(8.0);
        text_field(ui, &mut app.invite_email, INVITE_EMAIL_HINT);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(lbl(INVITE_ROLE_LABEL));
            for role in [ROLE_MEMBER, ROLE_ADMIN] {
                let selected = app.invite_role == role;
                let btn = egui::Button::new(
                    egui::RichText::new(role)
                        .size(11.0)
                        .color(if selected { t.accent_ink } else { t.text_secondary }),
                )
                .fill(if selected { t.accent } else { t.surface })
                .stroke(egui::Stroke::new(1.0_f32, if selected { t.accent } else { t.border }))
                .min_size(egui::vec2(62.0, 24.0));
                if ui.add(btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    app.invite_role = role.to_string();
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(
                    egui::DragValue::new(&mut app.invite_devices)
                        .range(MIN_INVITE_DEVICES..=MAX_INVITE_DEVICES),
                );
                ui.label(lbl(INVITE_DEVICES_LABEL));
            });
        });
        ui.add_space(10.0);
        let ready = !app.invite_email.trim().is_empty() && !pending;
        let btn = egui::Button::new(
            egui::RichText::new(INVITE_SEND).size(12.0).strong().color(t.accent_ink),
        )
        .fill(t.accent)
        .min_size(egui::vec2(130.0, 30.0));
        if ui.add_enabled(ready, btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            *action = Some(Action::CreateInvite);
        }
        if pending {
            ui.add_space(6.0);
            ui.spinner();
        }
        if let Some(message) = invite_error {
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(explain(&message, ERR_NO_MESH)).size(11.0).color(t.danger),
                )
                .wrap(),
            );
        }
        if let Some(invite) = invite {
            ui.push_id(&invite.id, |ui| {
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new(format!("{} {} · {}", INVITE_SENT, invite.email, invite.role))
                        .size(11.0)
                        .color(t.success),
                );
                ui.add_space(6.0);
                ui.label(lbl(INVITE_LINK_LABEL));
                ui.add_space(4.0);
                link_box(ui, &invite.invite_url);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    copy_row(ui, app, &invite.invite_url, action);
                    if !invite.expires_at.is_empty() {
                        let date = invite.expires_at.split('T').next().unwrap_or(&invite.expires_at);
                        ui.label(
                            egui::RichText::new(format!("{} {}", INVITE_EXPIRES, date))
                                .size(11.0)
                                .color(t.text_muted),
                        );
                    }
                });
            });
        }
    });
}

fn draw_settings(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    let mut action: Option<Action> = None;
    let account = app.account.clone();
    if back_bar(ui, SETTINGS_TITLE) {
        action = Some(Action::Open(View::Home));
    }

    card(ui, |ui| {
        ui.label(egui::RichText::new(SETTINGS_GENERAL).size(13.0).strong().color(t.text));
        ui.add_space(8.0);
        if ui.checkbox(&mut app.settings_start_login, SETTINGS_START_LOGIN).changed()
            && crate::autostart::set_enabled(app.settings_start_login).is_err()
        {
            app.settings_start_login = crate::autostart::is_enabled();
        }
        ui.checkbox(&mut app.auto_reconnect, SETTINGS_AUTO_RECONNECT);
    });

    ui.add_space(8.0);
    let joined = app.mesh_identity.is_some();
    card(ui, |ui| {
        ui.label(egui::RichText::new(SETTINGS_DEVICE_SECTION).size(13.0).strong().color(t.text));
        ui.add_space(8.0);
        ui.checkbox(&mut app.settings_magic_dns, MAGIC_DNS).on_hover_text(MAGIC_DNS_TIP);
        ui.add_space(12.0);
        if ui
            .add_enabled(joined, {
                egui::Button::new(egui::RichText::new(LEAVE_PROJECT).size(12.0).color(t.danger))
                    .fill(egui::Color32::TRANSPARENT)
                    .stroke(egui::Stroke::new(1.0_f32, t.danger))
                    .min_size(egui::vec2(190.0, 30.0))
            })
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            action = Some(Action::ConfirmLeave);
        }
    });

    ui.add_space(8.0);
    card(ui, |ui| {
        ui.label(egui::RichText::new(SETTINGS_ADVANCED).size(13.0).strong().color(t.text));
        ui.add_space(8.0);
        ui.label(lbl(SETTINGS_ROUTES_LABEL));
        text_field(ui, &mut app.settings_advertise_routes, SETTINGS_ROUTES_HINT);
        ui.add_space(10.0);
        ui.label(lbl(SETTINGS_HOST_LABEL));
        text_field(ui, &mut app.settings_api_host, crate::api::DEFAULT_API_HOST);
        ui.add_space(4.0);
        ui.label(egui::RichText::new(SIGNIN_ADVANCED_HINT).size(10.0).color(t.text_muted));
    });

    ui.add_space(8.0);
    card(ui, |ui| {
        ui.label(egui::RichText::new(ACCOUNT_SECTION).size(13.0).strong().color(t.text));
        ui.add_space(8.0);
        if let Some(ref email) = account {
            ui.horizontal(|ui| {
                avatar(ui, email);
                ui.label(egui::RichText::new(email).size(12.0).color(t.text_secondary));
            });
        }
        ui.add_space(12.0);
        if ghost_button(ui, SIGN_OUT, t.danger, 190.0).clicked() {
            action = Some(Action::ConfirmSignOut);
        }
    });
    ui.add_space(8.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new(version_text()).size(10.0).color(t.text_muted));
    });
    ui.add_space(10.0);

    app.persist_settings();
    if let Some(action) = action {
        app.apply(action);
    }
}

fn draw_update_banner(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    if app.updating.load(Ordering::Relaxed) {
        return;
    }
    let info = app.update_info.lock().unwrap().clone();
    let Some(info) = info.filter(|i| i.has_update) else { return };
    ui.add_space(10.0);
    egui::Frame::default()
        .fill(t.accent.linear_multiply(0.1))
        .corner_radius(cr(12))
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("v{} {}", info.version, UPDATE_AVAILABLE))
                        .size(13.0)
                        .strong()
                        .color(t.text),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let btn = egui::Button::new(
                        egui::RichText::new(UPDATE_ACTION).size(12.0).strong().color(t.accent_ink),
                    )
                    .fill(t.accent)
                    .min_size(egui::vec2(80.0, 30.0));
                    if ui.add(btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        app.start_update(info.download_url.clone());
                    }
                });
            });
        });
    ui.add_space(6.0);
}

fn fmt_since(unix: i64) -> String {
    let now = now_secs() as i64;
    if unix <= 0 || now <= unix {
        return NEVER_SEEN.to_string();
    }
    format!("{} ago", fmt_uptime((now - unix) as u64))
}

fn fmt_uptime(s: u64) -> String {
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m{}s", s / 60, s % 60)
    } else {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    }
}

fn logo_texture(ctx: &egui::Context) -> egui::TextureHandle {
    ctx.data(|d| d.get_temp::<egui::TextureHandle>(egui::Id::new("ng_logo")))
        .unwrap_or_else(|| {
            let png = include_bytes!("../assets/logo-64.png");
            let img = image::load_from_memory(png).unwrap().to_rgba8();
            let size = [img.width() as _, img.height() as _];
            let pixels = img.into_raw();
            let ci = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
            let tex = ctx.load_texture("logo", ci, egui::TextureOptions::LINEAR);
            ctx.data_mut(|d| d.insert_temp(egui::Id::new("ng_logo"), tex.clone()));
            tex
        })
}

fn draw_logo(ui: &mut egui::Ui, size: f32) {
    let tex = logo_texture(ui.ctx());
    ui.add(egui::Image::new(&tex).fit_to_exact_size(egui::vec2(size, size)));
}

fn generate_app_icon() -> egui::IconData {
    let png = include_bytes!("../assets/logo-128.png");
    let img = image::load_from_memory(png).unwrap().to_rgba8();
    egui::IconData { width: img.width(), height: img.height(), rgba: img.into_raw() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW_FAILURES: [&str; 8] = [
        "list projects: HTTP 404 — 404 page not found",
        "netmap: HTTP 401 — {\"error\":\"unauthorized\"}",
        "Could not join the mesh network: HTTP 402 — {\"error\":\"plan_required\"}",
        "enroll: HTTP 409 — {\"error\":\"project_required\"}",
        "create project: HTTP 500 — upstream unavailable",
        "connect api.nexguard.sh:443: Connection refused (os error 61)",
        "parse projects: expected value at line 1 column 1 — <html>",
        "list devices: HTTP 418 — teapot",
    ];

    fn row(name: &str, shares: bool, is_self: bool) -> DeviceRow {
        DeviceRow {
            device_id: format!("dev_{}", name),
            name: name.to_string(),
            ip: "100.64.0.2".to_string(),
            is_self,
            shares_internet: shares,
            online: true,
            ..DeviceRow::default()
        }
    }

    #[test]
    fn no_failure_ever_reaches_the_user_as_an_http_status() {
        for raw in RAW_FAILURES {
            let shown = explain(raw, ERR_NO_MESH);
            assert!(!shown.contains(HTTP_MARKER), "{} leaked a status: {}", raw, shown);
            assert!(shown.ends_with('.'), "{} is not a sentence: {}", raw, shown);
        }
    }

    #[test]
    fn a_failure_to_connect_is_explained_in_plain_language() {
        let raw = "enroll: HTTP 502 — {\"error\":\"bad gateway\"}";
        let shown = explain(raw, ERR_NO_MESH);
        assert_eq!(shown, ERR_SERVICE);
        assert!(!shown.contains(HTTP_MARKER));
    }

    #[test]
    fn a_missing_mesh_endpoint_points_at_the_control_plane() {
        assert_eq!(explain(RAW_FAILURES[0], ERR_NO_MESH), ERR_NO_MESH);
        assert_eq!(explain(RAW_FAILURES[0], ERR_NO_SIGNIN), ERR_NO_SIGNIN);
    }

    #[test]
    fn status_codes_map_to_their_own_sentence() {
        assert_eq!(explain(RAW_FAILURES[1], ERR_NO_MESH), ERR_EXPIRED);
        assert_eq!(explain(RAW_FAILURES[2], ERR_NO_MESH), ERR_PLAN);
        assert_eq!(explain(RAW_FAILURES[3], ERR_NO_MESH), ERR_PROJECT_REQUIRED);
        assert_eq!(explain(RAW_FAILURES[4], ERR_NO_MESH), ERR_SERVICE);
        assert_eq!(explain(RAW_FAILURES[5], ERR_NO_MESH), ERR_OFFLINE);
        assert_eq!(explain(RAW_FAILURES[6], ERR_NO_MESH), ERR_GENERIC);
    }

    #[test]
    fn the_two_conflict_codes_are_the_only_ones_with_their_own_sentence() {
        assert_eq!(
            explain("delete project: HTTP 409 — {\"error\":\"project_not_empty\"}", ERR_NO_MESH),
            ERR_PROJECT_NOT_EMPTY
        );
        assert_eq!(
            explain("create project: HTTP 409 — {\"error\":\"something_else\"}", ERR_NO_MESH),
            ERR_GENERIC
        );
    }

    #[test]
    fn sentences_written_by_the_api_layer_are_passed_through() {
        let written = "Your plan does not include team members.";
        assert_eq!(explain(written, ERR_NO_MESH), written);
    }

    #[test]
    fn counts_read_naturally_for_one_and_many() {
        assert_eq!(plural(1, WORD_DEVICE, WORD_DEVICES), "1 device");
        assert_eq!(plural(3, WORD_DEVICE, WORD_DEVICES), "3 devices");
        assert_eq!(plural(0, WORD_PERSON, WORD_PEOPLE), "0 people");
    }

    #[test]
    fn internet_routing_defaults_to_direct() {
        let rows = vec![row("macbook", false, true), row("home-pc", true, false)];
        assert_eq!(exit_label(None, &rows), EXIT_DIRECT);
        assert_eq!(exit_label(Some("dev_home-pc"), &rows), "home-pc");
    }

    #[test]
    fn only_another_device_that_shares_can_be_picked_as_the_exit() {
        let rows = vec![
            row("macbook", true, true),
            row("home-pc", false, false),
            row("frankfurt", true, false),
        ];
        let names: Vec<&str> = exit_candidates(&rows).iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["frankfurt"]);
    }

    #[test]
    fn an_exit_that_is_gone_falls_back_to_direct_instead_of_naming_it() {
        let rows = vec![row("macbook", false, true)];
        assert_eq!(exit_label(Some("dev_frankfurt"), &rows), EXIT_DIRECT);
    }

    #[test]
    fn a_device_row_reads_as_a_sentence_of_facts() {
        let mut this = row("macbook", false, true);
        assert_eq!(details_line(&this), THIS_DEVICE_TAG);
        this.shares_internet = true;
        assert_eq!(details_line(&this), "this device · shares internet");

        let mut peer = row("home-pc", true, false);
        peer.path = Some(PeerPath::Direct);
        peer.rtt_ms = Some(12);
        assert_eq!(details_line(&peer), "direct · 12ms · shares internet");

        let mut box_ = row("frankfurt", true, false);
        box_.path = Some(PeerPath::Relay);
        box_.provisioned = true;
        assert_eq!(details_line(&box_), "relay · provisioned · shares internet");
    }

    #[test]
    fn a_device_the_session_has_not_seen_is_only_called_offline_when_it_is() {
        let mut unseen = row("home-pc", false, false);
        assert_eq!(details_line(&unseen), "");
        unseen.online = false;
        assert_eq!(details_line(&unseen), PATH_OFFLINE);
    }

    fn identity(network_id: &str, project_id: &str) -> MeshIdentity {
        serde_json::from_str(&format!(
            "{{\"network\":{{\"id\":\"{}\",\"project_id\":\"{}\"}}}}",
            network_id, project_id
        ))
        .unwrap()
    }

    fn project(id: &str, network_id: Option<&str>) -> Project {
        let network = match network_id {
            Some(network_id) => format!(",\"network\":{{\"id\":\"{}\"}}", network_id),
            None => String::new(),
        };
        serde_json::from_str(&format!("{{\"id\":\"{}\"{}}}", id, network)).unwrap()
    }

    #[test]
    fn an_identity_enrolled_before_projects_is_kept_when_its_network_matches() {
        let legacy = identity("net_1", "");
        assert!(identity_serves(&legacy, &project("prj_1", Some("net_1"))));
        assert!(!identity_serves(&legacy, &project("prj_2", Some("net_2"))));
    }

    #[test]
    fn an_identity_that_names_its_project_is_kept_even_without_network_data() {
        let current = identity("net_1", "prj_1");
        assert!(identity_serves(&current, &project("prj_1", None)));
        assert!(!identity_serves(&current, &project("prj_2", None)));
    }

    #[test]
    fn an_identity_from_another_project_is_not_reused() {
        let other = identity("net_9", "prj_9");
        assert!(!identity_serves(&other, &project("prj_1", Some("net_1"))));
    }

    #[test]
    fn a_status_is_only_read_after_the_http_marker() {
        assert_eq!(http_status("list devices: HTTP 404 — nope"), Some(404));
        assert_eq!(http_status("connect 10.0.0.1:443: refused"), None);
    }
}
