use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::profiles::ServerProfile;
use crate::vpn::{VpnConfig, VpnStatus};

#[derive(Clone, PartialEq)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

enum View { ServerList, AddServer, Login, Settings }

struct VpnApp {
    profiles: Vec<ServerProfile>,
    selected: Option<usize>,
    view: View,
    new_name: String,
    new_server: String,
    new_token: String,
    new_internet: bool,
    new_share_lan: bool,
    show_token: bool,
    state: Arc<Mutex<ConnectionState>>,
    status: Arc<Mutex<Option<VpnStatus>>>,
    shutdown: Arc<AtomicBool>,
    connect_trigger: Arc<AtomicBool>,
    selected_server: Arc<AtomicUsize>,
    tray: Option<crate::tray::NexTray>,
    update_info: Arc<Mutex<Option<crate::api::UpdateInfo>>>,
    updating: Arc<AtomicBool>,
    update_result: Arc<Mutex<Option<Result<(), String>>>>,
    confirm_delete: Option<usize>,
    editing_idx: Option<usize>,
    reconnect_pending: bool,
    quit_cleanup_done: bool,
    login_in_progress: bool,
    login_result: Arc<Mutex<Option<Result<crate::api::ConnectBundle, String>>>>,
    login_error: Option<String>,
    settings_connection_mode: ConnectionMode,
    settings_kill_switch: bool,
    settings_dns_leak: bool,
    settings_advertise_routes: String,
    new_auto_connect: bool,
    auto_reconnect: bool,
    sync_in_progress: bool,
    sync_result: Arc<Mutex<Option<Result<Vec<crate::api::SyncedProfile>, String>>>>,
    sync_error: Option<String>,
    netmon: crate::netmon::NetMonitor,
    last_net_epoch: u64,
    connected_frame_since: Option<std::time::Instant>,
    settings_start_login: bool,
}

#[derive(Clone, PartialEq)]
enum ConnectionMode {
    Auto,
    DirectUdp,
    TlsRelay,
}

impl Default for VpnApp {
    fn default() -> Self {
        let update_info: Arc<Mutex<Option<crate::api::UpdateInfo>>> = Arc::new(Mutex::new(None));
        {
            let slot = Arc::clone(&update_info);
            std::thread::spawn(move || {
                if let Some(info) = crate::api::check_update() {
                    *slot.lock().unwrap() = Some(info);
                }
            });
        }
        let profiles = crate::profiles::load();
        let settings = crate::profiles::load_settings();
        let view = if profiles.is_empty() { View::Login } else { View::ServerList };
        let sync_result: Arc<Mutex<Option<Result<Vec<crate::api::SyncedProfile>, String>>>> = Arc::new(Mutex::new(None));
        if !profiles.is_empty() {
            let token = profiles[0].token.clone();
            let slot = Arc::clone(&sync_result);
            std::thread::spawn(move || {
                let result = crate::api::fetch_profiles(&token);
                *slot.lock().unwrap() = Some(result);
            });
        }
        let connection_mode = match settings.connection_mode.as_str() {
            "direct" => ConnectionMode::DirectUdp,
            "tls" => ConnectionMode::TlsRelay,
            _ => ConnectionMode::Auto,
        };
        let has_profiles = !profiles.is_empty();
        Self {
            selected: if profiles.is_empty() { None } else { Some(0) },
            profiles,
            view,
            new_name: String::new(),
            new_server: String::new(),
            new_token: String::new(),
            new_internet: true,
            new_share_lan: false,
            show_token: false,
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            status: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(AtomicBool::new(false)),
            connect_trigger: Arc::new(AtomicBool::new(false)),
            selected_server: Arc::new(AtomicUsize::new(usize::MAX)),
            tray: None,
            update_info,
            updating: Arc::new(AtomicBool::new(false)),
            update_result: Arc::new(Mutex::new(None)),
            confirm_delete: None,
            editing_idx: None,
            reconnect_pending: false,
            quit_cleanup_done: false,
            login_in_progress: false,
            login_result: Arc::new(Mutex::new(None)),
            login_error: None,
            settings_connection_mode: connection_mode,
            settings_kill_switch: settings.kill_switch,
            settings_dns_leak: settings.dns_leak_protection,
            settings_advertise_routes: settings.advertise_routes,
            new_auto_connect: false,
            auto_reconnect: settings.auto_reconnect,
            sync_in_progress: has_profiles,
            sync_result,
            sync_error: None,
            netmon: crate::netmon::NetMonitor::start(),
            last_net_epoch: 0,
            connected_frame_since: None,
            settings_start_login: crate::autostart::is_enabled(),
        }
    }
}

impl VpnApp {
    fn connect_selected(&mut self) {
        let Some(idx) = self.selected else { return };
        let Some(profile) = self.profiles.get(idx) else { return };
        let profile = profile.clone();
        if let Some(p) = self.profiles.get_mut(idx) {
            p.last_used = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            crate::profiles::save(&self.profiles);
        }
        self.shutdown = Arc::new(AtomicBool::new(false));
        *self.state.lock().unwrap() = ConnectionState::Connecting;
        let state = Arc::clone(&self.state);
        let status_slot = Arc::clone(&self.status);
        let shutdown = Arc::clone(&self.shutdown);
        let force_direct = self.settings_connection_mode == ConnectionMode::DirectUdp;
        let force_relay = self.settings_connection_mode == ConnectionMode::TlsRelay;
        let kill_switch = self.settings_kill_switch;
        let dns_leak = self.settings_dns_leak;
        let extra_routes: Vec<String> = if self.settings_advertise_routes.is_empty() {
            Vec::new()
        } else {
            self.settings_advertise_routes.split(',').map(|s| s.trim().to_string()).collect()
        };
        std::thread::spawn(move || {
            let mut server = profile.server.clone();
            let mut relay: Option<String> = None;
            let mut relay_name: Option<String> = None;
            let mut join_url: Option<String> = None;

            let cached = if !profile.token.is_empty() {
                crate::cache::load(&profile.token)
            } else {
                None
            };

            if server.is_empty() && !profile.token.is_empty() {
                if let Some(ref c) = cached {
                    server = c.server.clone().unwrap_or_default();
                    relay = c.relay.clone();
                    relay_name = c.relay_name.clone();
                    join_url = c.join_url.clone();
                    if server.is_empty() && relay.is_some() {
                        server = "relay".to_string();
                    }
                } else {
                    match crate::api::try_fetch_connect_info(&profile.token) {
                        Ok(info) => {
                            join_url = info.join_url.clone();
                            if let Some(s) = info.server.clone() {
                                server = s;
                            } else if let Some(r) = info.relay.clone() {
                                relay = Some(r);
                                relay_name = info.relay_name.clone();
                                server = "relay".to_string();
                            }
                            crate::cache::save(
                                &profile.token,
                                info.server,
                                info.relay,
                                info.relay_name,
                                info.join_url,
                                serde_json::Value::Null,
                            );
                        }
                        Err(e) => {
                            *state.lock().unwrap() = ConnectionState::Error(e);
                            return;
                        }
                    }
                }
            }

            if server.is_empty() && join_url.is_none() {
                *state.lock().unwrap() = ConnectionState::Error("Server not found. Check your token.".into());
                return;
            }
            if server.is_empty() { server = "api-proxy".to_string(); }

            let effective_relay = if force_direct { None } else if force_relay { relay.or_else(|| relay_name.clone()) } else { relay };

            let config = VpnConfig {
                server,
                token: profile.token.clone(),
                internet: profile.internet,
                share_lan: profile.share_lan,
                relay: effective_relay,
                relay_name,
                join_url,
                kill_switch,
                dns_leak_protection: dns_leak,
                extra_routes,
                ..VpnConfig::default()
            };
            match crate::vpn::connect(config, Arc::clone(&shutdown)) {
                Ok(st) => {
                    let geo_slot = Arc::clone(&st.geo);
                    let geo_server = st.server.clone();
                    let geo_port = st.control_port;
                    let geo_token = profile.token.clone();
                    *status_slot.lock().unwrap() = Some(st);
                    *state.lock().unwrap() = ConnectionState::Connected;
                    std::thread::spawn(move || {
                        if let Some(info) = crate::api::fetch_geo_info(&geo_server, geo_port, &geo_token) {
                            *geo_slot.lock().unwrap() = Some(info);
                        }
                    });
                }
                Err(e) => { *state.lock().unwrap() = ConnectionState::Error(e); }
            }
        });
    }

    fn disconnect(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let status_slot = Arc::clone(&self.status);
        let state = Arc::clone(&self.state);
        *self.state.lock().unwrap() = ConnectionState::Connecting;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            if let Some(status) = status_slot.lock().unwrap().take() {
                if status.internet_mode {
                    crate::route::emergency_cleanup(&status.tun_name);
                }
            }
            *state.lock().unwrap() = ConnectionState::Disconnected;
        });
    }

    fn quit_cleanup(&mut self) {
        if self.quit_cleanup_done { return; }
        self.quit_cleanup_done = true;
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(status) = self.status.lock().unwrap().take() {
            if status.internet_mode {
                crate::route::emergency_cleanup(&status.tun_name);
            }
        }
        #[cfg(unix)]
        if let Some(dir) = crate::profiles::config_dir() {
            let _ = std::fs::remove_file(dir.join(GUI_SOCK));
        }
    }

    fn save_new_server(&mut self) {
        let name = if self.new_name.is_empty() { "VPN Server".to_string() } else { self.new_name.clone() };
        let profile = ServerProfile {
            name,
            server: self.new_server.clone(),
            token: self.new_token.clone(),
            server_id: String::new(),
            internet: self.new_internet,
            share_lan: self.new_share_lan,
            auto_connect: self.new_auto_connect,
            last_used: 0,
        };
        if let Some(idx) = self.editing_idx.take() {
            if idx < self.profiles.len() {
                self.profiles[idx] = profile;
                crate::profiles::save(&self.profiles);
                self.selected = Some(idx);
            }
        } else {
            crate::profiles::add(&mut self.profiles, profile);
            self.selected = Some(self.profiles.len() - 1);
        }
        self.sync_tray_servers();
        self.new_name.clear();
        self.new_server.clear();
        self.new_token.clear();
        self.new_internet = true;
        self.new_share_lan = false;
        self.new_auto_connect = false;
        self.view = View::ServerList;
    }

    fn start_edit(&mut self, idx: usize) {
        if let Some(p) = self.profiles.get(idx) {
            self.new_name = p.name.clone();
            self.new_server = p.server.clone();
            self.new_token = p.token.clone();
            self.new_internet = p.internet;
            self.new_share_lan = p.share_lan;
            self.new_auto_connect = p.auto_connect;
            self.editing_idx = Some(idx);
            self.view = View::AddServer;
        }
    }

    fn remove_selected(&mut self) {
        if let Some(idx) = self.selected {
            crate::profiles::remove(&mut self.profiles, idx);
            self.selected = if self.profiles.is_empty() { None } else { Some(0) };
            self.sync_tray_servers();
        }
    }

    fn sync_tray_servers(&mut self) {
        if let Some(ref mut tray) = self.tray {
            tray.update_servers(&self.profiles, self.selected.unwrap_or(0));
        }
    }

    fn start_update(&mut self, url: String) {
        if self.updating.load(Ordering::Relaxed) { return; }
        self.updating.store(true, Ordering::Relaxed);
        let updating = Arc::clone(&self.updating);
        let result = Arc::clone(&self.update_result);
        std::thread::spawn(move || {
            let r = crate::api::self_update(&url);
            *result.lock().unwrap() = Some(r);
            updating.store(false, Ordering::Relaxed);
        });
    }

    fn start_login(&mut self) {
        if self.login_in_progress { return; }
        self.login_in_progress = true;
        self.login_error = None;
        *self.login_result.lock().unwrap() = None;
        let result = Arc::clone(&self.login_result);
        std::thread::spawn(move || {
            match crate::api::request_device_login() {
                Ok(resp) => {
                    let _ = open::that(&resp.login_url);
                    let max_polls = 200u32;
                    for _ in 0..max_polls {
                        std::thread::sleep(std::time::Duration::from_secs(3));
                        match crate::api::poll_device_login(&resp.token) {
                            Ok(Some(bundle)) => {
                                *result.lock().unwrap() = Some(Ok(bundle));
                                return;
                            }
                            Ok(None) => continue,
                            Err(e) => {
                                *result.lock().unwrap() = Some(Err(e));
                                return;
                            }
                        }
                    }
                    *result.lock().unwrap() = Some(Err("Login timed out".into()));
                }
                Err(e) => {
                    *result.lock().unwrap() = Some(Err(e));
                }
            }
        });
    }

    fn start_sync(&mut self) {
        let token = match self.profiles.first() {
            Some(p) if !p.token.is_empty() => p.token.clone(),
            _ => return,
        };
        if self.sync_in_progress { return; }
        self.sync_in_progress = true;
        self.sync_error = None;
        *self.sync_result.lock().unwrap() = None;
        let slot = Arc::clone(&self.sync_result);
        std::thread::spawn(move || {
            let result = crate::api::fetch_profiles(&token);
            *slot.lock().unwrap() = Some(result);
        });
    }
}

const APP_NAME: &str = "NexGuard VPN";
const DEPLOY_URL: &str = "https://nexguard.sh/deploy";

static SHOW_REQUEST: std::sync::atomic::AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
const GUI_SOCK: &str = "gui.sock";

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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
    }
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let mut buf = [0u8; 16];
                let _ = s.read(&mut buf);
                SHOW_REQUEST.store(true, Ordering::Relaxed);
            }
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
        if cls.is_null() || shared_sel.is_null() || policy_sel.is_null() { return; }
        let send0: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let app = send0(cls, shared_sel);
        if app.is_null() { return; }
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

pub fn run_gui_with(token: Option<String>, name: Option<String>, internet: bool) {
    #[cfg(unix)]
    if !claim_single_instance() {
        return;
    }
    let icon = generate_app_icon();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 620.0])
            .with_min_inner_size([400.0, 560.0])
            .with_maximize_button(false)
            .with_title(APP_NAME)
            .with_icon(std::sync::Arc::new(icon)),
        ..Default::default()
    };
    eframe::run_native(APP_NAME, options, Box::new(move |cc| {
        setup_style(&cc.egui_ctx);
        let mut app = VpnApp::default();

        let prefetch_hosts: Vec<String> = std::iter::once(
            std::env::var("NEXGUARD_API_HOST").unwrap_or_else(|_| "api.nexguard.sh".to_string()),
        )
        .chain(app.profiles.iter().filter_map(|p| {
            if p.server.is_empty() { None } else { Some(p.server.clone()) }
        }))
        .collect();
        std::thread::spawn(move || {
            use std::net::ToSocketAddrs;
            for host in prefetch_hosts {
                let target = if host.contains(':') { host } else { format!("{}:443", host) };
                let _ = target.to_socket_addrs();
            }
        });

        app.tray = crate::tray::NexTray::new(
            Arc::clone(&app.status),
            Arc::clone(&app.connect_trigger),
            Arc::clone(&app.selected_server),
            &app.profiles,
        );

        if let Some(t) = token {
            let profile_name = name.unwrap_or_else(|| "VPN Server".to_string());
            let profile = crate::profiles::ServerProfile {
                name: profile_name,
                server: String::new(),
                token: t,
                server_id: String::new(),
                internet,
                share_lan: false,
                auto_connect: false,
                last_used: 0,
            };
            crate::profiles::add(&mut app.profiles, profile);
            app.selected = Some(app.profiles.len() - 1);
            app.connect_selected();
        } else if let Some(idx) = app.profiles.iter().position(|p| p.auto_connect) {
            app.selected = Some(idx);
            app.view = View::ServerList;
            app.connect_selected();
        }
        Ok(Box::new(app))
    })).ok();
}

fn cr(r: u8) -> egui::CornerRadius { egui::CornerRadius::same(r) }

struct Theme {
    bg: egui::Color32,
    surface: egui::Color32,
    surface_hover: egui::Color32,
    border: egui::Color32,
    border_active: egui::Color32,
    text: egui::Color32,
    text_secondary: egui::Color32,
    text_muted: egui::Color32,
    accent: egui::Color32,
    success: egui::Color32,
    danger: egui::Color32,
    warning: egui::Color32,
    input_bg: egui::Color32,
}

fn dark_theme() -> Theme {
    Theme {
        bg: egui::Color32::from_rgb(9, 9, 11),
        surface: egui::Color32::from_rgb(24, 24, 27),
        surface_hover: egui::Color32::from_rgb(39, 39, 42),
        border: egui::Color32::from_rgb(39, 39, 42),
        border_active: egui::Color32::from_rgb(56, 189, 248),
        text: egui::Color32::from_rgb(250, 250, 250),
        text_secondary: egui::Color32::from_rgb(161, 161, 170),
        text_muted: egui::Color32::from_rgb(113, 113, 122),
        accent: egui::Color32::from_rgb(56, 189, 248),
        success: egui::Color32::from_rgb(34, 197, 94),
        danger: egui::Color32::from_rgb(239, 68, 68),
        warning: egui::Color32::from_rgb(234, 179, 8),
        input_bg: egui::Color32::from_rgb(15, 15, 18),
    }
}

fn theme() -> &'static Theme {
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

    for w in [&mut style.visuals.widgets.noninteractive, &mut style.visuals.widgets.inactive, &mut style.visuals.widgets.hovered, &mut style.visuals.widgets.active] {
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

fn lbl(t: &str) -> egui::RichText {
    egui::RichText::new(t).size(12.0).color(theme().text_muted)
}

fn status_dot(ui: &mut egui::Ui, filled: bool, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    if filled {
        ui.painter().circle_filled(rect.center(), 4.5, color);
    } else {
        ui.painter().circle_stroke(rect.center(), 4.5, egui::Stroke::new(1.5_f32, color));
    }
}

fn read_clipboard() -> Option<String> {
    arboard::Clipboard::new().ok()?.get_text().ok()
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
            self.disconnect();
        }

        if SHOW_REQUEST.swap(false, Ordering::Relaxed) {
            show_window(ctx);
        }

        let quit = self.tray.as_ref().map_or(false, |t| t.quit_requested);
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

        let state = self.state.lock().unwrap().clone();
        let status = self.status.lock().unwrap().clone();

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
            match state {
                ConnectionState::Connected => {
                    draw_header_connected(ui, self);
                    ui.add_space(6.0);
                    draw_connected(ui, &status);
                    ui.add_space(6.0);
                    draw_server_view(ui, self);
                }
                ConnectionState::Connecting => {
                    let t = theme();
                    draw_header(ui);
                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        ui.spinner();
                        ui.add_space(4.0);
                        let is_disconnecting = self.shutdown.load(Ordering::Relaxed);
                        let msg = if is_disconnecting { "Disconnecting..." } else { "Connecting..." };
                        ui.label(egui::RichText::new(msg).size(14.0).color(t.warning));
                    });
                    ui.add_space(6.0);
                    draw_server_view(ui, self);
                    ctx.request_repaint_after(std::time::Duration::from_millis(200));
                }
                ConnectionState::Error(ref msg) => {
                    let t = theme();
                    draw_header(ui);
                    draw_server_view(ui, self);
                    ui.add_space(6.0);
                    let mut dismissed = false;
                    egui::Frame::default()
                        .fill(egui::Color32::from_rgba_premultiplied(239, 68, 68, 25))
                        .corner_radius(cr(10)).inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(msg).size(12.0).color(t.danger));
                            ui.add_space(4.0);
                            if ui.add(egui::Button::new(egui::RichText::new("Dismiss").size(11.0).color(t.text_secondary))
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::new(1.0_f32, t.danger))).clicked() {
                                dismissed = true;
                            }
                        });
                    if dismissed {
                        *self.state.lock().unwrap() = ConnectionState::Disconnected;
                    }
                }
                ConnectionState::Disconnected => {
                    draw_header(ui);
                    draw_server_view(ui, self);
                }
            }
            draw_update_banner(ui, self);
            });
        });

        if self.reconnect_pending && matches!(state, ConnectionState::Disconnected | ConnectionState::Error(_)) {
            self.reconnect_pending = false;
            self.connect_selected();
        }

        let tray_server = self.selected_server.load(Ordering::Relaxed);
        if tray_server != usize::MAX {
            self.selected_server.store(usize::MAX, Ordering::Relaxed);
            if tray_server < self.profiles.len() {
                self.selected = Some(tray_server);
                self.sync_tray_servers();
            }
        }

        if self.connect_trigger.swap(false, Ordering::Relaxed) {
            if matches!(state, ConnectionState::Connected | ConnectionState::Connecting) {
                self.disconnect();
                self.reconnect_pending = true;
            } else {
                self.connect_selected();
            }
        }

        if self.login_in_progress {
            let login_done = self.login_result.lock().unwrap().clone();
            if let Some(result) = login_done {
                self.login_in_progress = false;
                match result {
                    Ok(bundle) => {
                        let profile = ServerProfile {
                            name: if bundle.email.is_empty() { "My VPN".into() } else { bundle.email },
                            server: String::new(),
                            token: bundle.device_jwt,
                            server_id: bundle.server_id,
                            internet: true,
                            share_lan: false,
                            auto_connect: true,
                            last_used: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        };
                        crate::profiles::add(&mut self.profiles, profile);
                        self.selected = Some(self.profiles.len() - 1);
                        self.sync_tray_servers();
                        self.view = View::ServerList;
                        self.connect_selected();
                    }
                    Err(e) => { self.login_error = Some(e); }
                }
            }
        }

        if self.sync_in_progress {
            let sync_done = self.sync_result.lock().unwrap().clone();
            if let Some(result) = sync_done {
                self.sync_in_progress = false;
                match result {
                    Ok(synced) => {
                        for sp in synced {
                            let existing = self.profiles.iter().find(|p| {
                                (!p.server_id.is_empty() && p.server_id == sp.server_id)
                                    || (!p.token.is_empty() && p.token == sp.device_jwt)
                            });
                            if existing.is_none() {
                                let profile = ServerProfile {
                                    name: if sp.email.is_empty() { sp.name.clone() } else { sp.email.clone() },
                                    server: String::new(),
                                    token: sp.device_jwt.clone(),
                                    server_id: sp.server_id.clone(),
                                    internet: true,
                                    share_lan: false,
                                    auto_connect: false,
                                    last_used: 0,
                                };
                                crate::profiles::add(&mut self.profiles, profile);
                            } else if let Some(p) = self.profiles.iter_mut().find(|p| !p.server_id.is_empty() && p.server_id == sp.server_id) {
                                if p.token != sp.device_jwt {
                                    p.token = sp.device_jwt;
                                }
                            }
                        }
                        crate::profiles::save(&self.profiles);
                        self.sync_tray_servers();
                    }
                    Err(e) => { self.sync_error = Some(e); }
                }
            }
        }

        let now_connected = matches!(state, ConnectionState::Connected);
        if now_connected {
            if self.connected_frame_since.is_none() {
                self.connected_frame_since = Some(std::time::Instant::now());
            }
            if let Some(ref st) = status {
                if !st.net_target.is_empty() {
                    self.netmon.set_target(&st.net_target);
                }
            }
        } else {
            self.connected_frame_since = None;
        }
        let net_epoch = self.netmon.epoch();
        if net_epoch != self.last_net_epoch {
            self.last_net_epoch = net_epoch;
            // Route flips caused by our own tunnel setup land within the first
            // seconds of a session — only real roaming/wake events after that
            // should force a restart.
            let grace_over = self
                .connected_frame_since
                .map(|t| t.elapsed().as_secs() >= 6)
                .unwrap_or(false);
            if now_connected && grace_over && self.auto_reconnect {
                self.reconnect_pending = true;
                self.disconnect();
            }
        }
        if let Some(ref st) = status {
            if st.connection_dropped.swap(false, Ordering::Relaxed) {
                if let Some(st) = self.status.lock().unwrap().take() {
                    if st.internet_mode {
                        crate::route::emergency_cleanup(&st.tun_name);
                    }
                }
                if self.auto_reconnect && !self.shutdown.load(Ordering::Relaxed) {
                    *self.state.lock().unwrap() = ConnectionState::Connecting;
                    self.connect_selected();
                } else {
                    *self.state.lock().unwrap() = ConnectionState::Disconnected;
                }
            }
        }

        let repaint_interval = if matches!(state, ConnectionState::Connected | ConnectionState::Connecting) {
            200
        } else {
            500
        };
        ctx.request_repaint_after(std::time::Duration::from_millis(repaint_interval));
    }
}

fn draw_header(ui: &mut egui::Ui) {
    let t = theme();
    ui.vertical_centered(|ui| {
        ui.add_space(12.0);
        draw_logo(ui);
        ui.add_space(6.0);
        ui.label(egui::RichText::new("NexGuard").size(22.0).strong().color(t.text));
        ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).size(10.0).color(t.text_muted));
        ui.add_space(12.0);
    });
}

fn draw_header_connected(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        draw_logo(ui);
        ui.add_space(8.0);
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("NexGuard").size(17.0).strong().color(t.text));
                ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).size(10.0).color(t.text_muted));
            });
            ui.horizontal(|ui| {
                status_dot(ui, true, t.success);
                ui.label(egui::RichText::new("Connected").size(12.0).strong().color(t.success));
            });
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(12.0);
            if ui.add(egui::Button::new(egui::RichText::new("Disconnect").size(12.0).color(t.text)).fill(t.danger)).clicked() {
                app.disconnect();
            }
        });
    });
    ui.add_space(4.0);
    ui.separator();
}

fn draw_server_view(ui: &mut egui::Ui, app: &mut VpnApp) {
    match app.view {
        View::ServerList => draw_server_list(ui, app),
        View::AddServer => draw_add_server(ui, app),
        View::Login => draw_login(ui, app),
        View::Settings => draw_settings(ui, app),
    }
}

fn draw_server_list(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    let current_state = app.state.lock().unwrap().clone();
    let is_connected = matches!(current_state, ConnectionState::Connected);
    let is_connecting = matches!(current_state, ConnectionState::Connecting);

    if app.profiles.is_empty() {
        draw_empty_state(ui, app);
        return;
    }

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Servers").size(14.0).strong().color(t.text));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(egui::Button::new(egui::RichText::new("⚙").size(14.0).color(t.text_muted)).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE)).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Settings").clicked() {
                app.view = View::Settings;
            }
            ui.add_space(4.0);
            let sync_icon = if app.sync_in_progress { "⟳" } else { "↻" };
            let sync_btn = egui::Button::new(egui::RichText::new(sync_icon).size(14.0).color(t.text_muted))
                .fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE);
            if ui.add(sync_btn).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Sync from cloud").clicked() {
                app.start_sync();
            }
            ui.add_space(4.0);
            let login_btn = egui::Button::new(egui::RichText::new("Login").size(12.0).strong().color(egui::Color32::WHITE))
                .fill(t.accent)
                .min_size(egui::vec2(60.0, 24.0));
            if ui.add(login_btn).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Add another account").clicked() {
                app.view = View::Login;
            }
            ui.add_space(4.0);
            let add_btn = egui::Button::new(egui::RichText::new("+").size(16.0).strong().color(t.text_secondary))
                .fill(egui::Color32::TRANSPARENT)
                .stroke(egui::Stroke::new(1.0_f32, t.border))
                .min_size(egui::vec2(28.0, 24.0));
            if ui.add(add_btn).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Add manually").clicked() {
                app.view = View::AddServer;
            }
        });
    });
    ui.add_space(6.0);

    let mut action_idx: Option<ServerAction> = None;
    let mut edit_idx: Option<usize> = None;

    for (i, profile) in app.profiles.iter().enumerate() {
        let is_selected = app.selected == Some(i);
        let is_active = (is_connected || is_connecting) && app.selected == Some(i);

        let (fill, stroke_color, stroke_width) = if is_active {
            (t.surface_hover, t.success, 1.5_f32)
        } else if is_selected {
            (t.surface_hover, t.accent, 1.5_f32)
        } else {
            (t.surface, t.border, 1.0_f32)
        };

        let card = egui::Frame::default()
            .fill(fill)
            .corner_radius(cr(10))
            .inner_margin(12.0)
            .stroke(egui::Stroke::new(stroke_width, stroke_color))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if is_active {
                        status_dot(ui, true, t.success);
                    }
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(&profile.name).size(13.0).strong().color(t.text));
                        let desc = if profile.server.is_empty() { "Auto-configured" } else { &profile.server };
                        ui.label(egui::RichText::new(desc).size(11.0).color(t.text_muted));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if is_active {
                            let (label, color) = if is_connecting {
                                ("Connecting...", t.warning)
                            } else {
                                ("Connected", t.success)
                            };
                            ui.label(egui::RichText::new(label).size(11.0).strong().color(color));
                        } else if is_selected && !is_connected {
                            ui.label(egui::RichText::new("Tap to connect").size(10.0).color(t.text_muted));
                        }

                        ui.add_space(8.0);

                        let menu_size = egui::vec2(24.0, 28.0);
                        let (menu_rect, menu_resp_raw) = ui.allocate_exact_size(menu_size, egui::Sense::click());
                        let menu_visible = menu_resp_raw.hovered() || ui.memory(|m| m.is_popup_open(egui::Id::new(("server_menu", i))));
                        let dot_color = if menu_visible { t.text } else { t.text_muted };
                        let cx = menu_rect.center().x;
                        let cy = menu_rect.center().y;
                        for dy in [-6.0, 0.0, 6.0] {
                            ui.painter().circle_filled(egui::pos2(cx, cy + dy), 1.8, dot_color);
                        }
                        let menu_resp = menu_resp_raw.on_hover_cursor(egui::CursorIcon::PointingHand);
                        let popup_id = egui::Id::new(("server_menu", i));
                        if menu_resp.clicked() {
                            ui.memory_mut(|m| m.toggle_popup(popup_id));
                        }
                        egui::popup_below_widget(ui, popup_id, &menu_resp, egui::PopupCloseBehavior::CloseOnClick, |ui| {
                            ui.set_min_width(120.0);
                            if ui.add(egui::Button::new(
                                egui::RichText::new("Edit").size(12.0).color(t.text)
                            ).fill(egui::Color32::TRANSPARENT).min_size(egui::vec2(110.0, 24.0))).clicked() {
                                edit_idx = Some(i);
                            }
                            if ui.add(egui::Button::new(
                                egui::RichText::new("Delete").size(12.0).color(t.danger)
                            ).fill(egui::Color32::TRANSPARENT).min_size(egui::vec2(110.0, 24.0))).clicked() {
                                ui.ctx().data_mut(|d| d.insert_temp(egui::Id::new("del_confirm_idx"), i));
                            }
                        });
                    });
                });
            });

        let card_rect = card.response.rect;
        let card_id = egui::Id::new(("server_card_click", i));
        if ui.interact(card_rect, card_id, egui::Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            if is_active {
                action_idx = Some(ServerAction::Disconnect);
            } else {
                action_idx = Some(ServerAction::Connect(i));
            }
        }

        ui.add_space(3.0);
    }

    match action_idx {
        Some(ServerAction::Connect(idx)) => {
            app.selected = Some(idx);
            app.sync_tray_servers();
            if matches!(current_state, ConnectionState::Connected | ConnectionState::Connecting) {
                app.disconnect();
                app.reconnect_pending = true;
            } else {
                app.connect_selected();
            }
        }
        Some(ServerAction::Disconnect) => {
            app.disconnect();
        }
        None => {}
    }

    if let Some(idx) = edit_idx {
        app.start_edit(idx);
    }

    if let Some(idx) = ui.ctx().data(|d| d.get_temp::<usize>(egui::Id::new("del_confirm_idx"))) {
        ui.ctx().data_mut(|d| d.remove_temp::<usize>(egui::Id::new("del_confirm_idx")));
        app.confirm_delete = Some(idx);
    }

    if let Some(idx) = app.confirm_delete {
        let name = app.profiles.get(idx).map(|p| p.name.clone()).unwrap_or_default();
        let t = theme();
        let mut close = false;
        let mut do_delete = false;
        egui::Window::new("Confirm deletion")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .fixed_size(egui::vec2(280.0, 120.0))
            .show(ui.ctx(), |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(format!("Remove \"{}\"?", name)).size(13.0).color(t.text));
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("This only removes it from this device.").size(11.0).color(t.text_muted));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.add_space(30.0);
                        if ui.add(egui::Button::new(egui::RichText::new("Cancel").size(12.0).color(t.text))
                            .fill(t.surface).min_size(egui::vec2(90.0, 28.0))).clicked() {
                            close = true;
                        }
                        ui.add_space(8.0);
                        if ui.add(egui::Button::new(egui::RichText::new("Delete").size(12.0).color(egui::Color32::WHITE))
                            .fill(t.danger).min_size(egui::vec2(90.0, 28.0))).clicked() {
                            do_delete = true;
                        }
                    });
                });
            });
        if do_delete {
            let deleting_active = app.selected == Some(idx)
                && matches!(*app.state.lock().unwrap(), ConnectionState::Connected | ConnectionState::Connecting);
            if deleting_active {
                app.reconnect_pending = false;
                app.disconnect();
            }
            app.selected = Some(idx);
            app.remove_selected();
            app.confirm_delete = None;
        } else if close {
            app.confirm_delete = None;
        }
    }
}

enum ServerAction {
    Connect(usize),
    Disconnect,
}

fn draw_empty_state(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    ui.add_space(20.0);
    ui.vertical_centered(|ui| {
        draw_logo(ui);
        ui.add_space(10.0);
        ui.label(egui::RichText::new("Welcome to NexGuard").size(18.0).strong().color(t.text));
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Add a server to get started").size(12.0).color(t.text_muted));
        ui.add_space(20.0);
    });

    card(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(6.0);
            let btn = egui::Button::new(egui::RichText::new("Login with Browser").size(14.0).strong().color(t.text))
                .fill(t.accent)
                .min_size(egui::vec2(220.0, 40.0));
            if ui.add(btn).clicked() {
                app.view = View::Login;
            }
            ui.add_space(8.0);
            if ui.add(egui::Button::new(egui::RichText::new("Add Manually").size(12.0).color(t.accent))
                .fill(egui::Color32::TRANSPARENT)
                .stroke(egui::Stroke::new(1.0_f32, t.accent))
                .min_size(egui::vec2(220.0, 36.0))).clicked() {
                app.view = View::AddServer;
            }
            ui.add_space(6.0);
        });
    });

    ui.add_space(14.0);
    ui.separator();
    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new("Don't have a server?").size(12.0).color(t.text_muted));
        ui.add_space(6.0);
        if ui.add(egui::Button::new(egui::RichText::new("Deploy VPN Server ↗").size(12.0).color(t.accent))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0_f32, t.accent))
            .min_size(egui::vec2(200.0, 36.0))).clicked() {
            let _ = open::that(DEPLOY_URL);
        }
    });
}

fn draw_add_server(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    let editing = app.editing_idx.is_some();
    ui.horizontal(|ui| {
        if ui.small_button("< Back").clicked() {
            app.editing_idx = None;
            app.new_name.clear();
            app.new_server.clear();
            app.new_token.clear();
            app.new_internet = true;
            app.new_share_lan = false;
            app.new_auto_connect = false;
            app.view = View::ServerList;
        }
        let title = if editing { "Edit Server" } else { "Add Server" };
        ui.label(egui::RichText::new(title).size(14.0).strong().color(t.text));
    });
    ui.add_space(6.0);

    card(ui, |ui| {
        ui.label(lbl("Server Name"));
        ui.add(egui::TextEdit::singleline(&mut app.new_name).hint_text("e.g. Office VPN").desired_width(f32::INFINITY).margin(egui::vec2(10.0, 10.0)));

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(lbl("Device Token"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(if app.show_token { "Hide" } else { "Show" }).clicked() {
                    app.show_token = !app.show_token;
                }
                if ui.small_button("Paste").clicked() {
                    if let Some(text) = read_clipboard() {
                        app.new_token = text.trim().to_owned();
                    }
                }
            });
        });
        let token_resp = ui.add(egui::TextEdit::singleline(&mut app.new_token).password(!app.show_token).hint_text("Paste token from dashboard").desired_width(f32::INFINITY).margin(egui::vec2(10.0, 10.0)));
        token_resp.context_menu(|ui| {
            if ui.button("Paste").clicked() {
                if let Some(text) = read_clipboard() {
                    app.new_token = text.trim().to_owned();
                }
                ui.close_menu();
            }
            if ui.button("Clear").clicked() {
                app.new_token.clear();
                ui.close_menu();
            }
        });

        ui.add_space(8.0);
        ui.checkbox(&mut app.new_internet, "Route all traffic through VPN");
        ui.checkbox(&mut app.new_share_lan, "Allow other peers to access my local network");
        ui.checkbox(&mut app.new_auto_connect, "Connect automatically on startup");
    });

    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        let ok = !app.new_token.is_empty();
        let label = if editing { "Save" } else { "Save & Connect" };
        let btn = egui::Button::new(egui::RichText::new(label).size(14.0).strong().color(t.text))
            .fill(if ok { t.accent } else { t.surface_hover })
            .min_size(egui::vec2(200.0, 40.0));
        if ui.add_enabled(ok, btn).clicked() {
            let was_editing = editing;
            app.save_new_server();
            if !was_editing {
                app.connect_selected();
            }
        }
    });

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new("Don't have a server?").size(12.0).color(t.text_muted));
        ui.add_space(6.0);
        if ui.add(egui::Button::new(egui::RichText::new("Deploy VPN Server").size(12.0).color(t.accent))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0_f32, t.accent))
            .min_size(egui::vec2(200.0, 36.0))).clicked() {
            let _ = open::that(DEPLOY_URL);
        }
    });
}

fn draw_login(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    ui.horizontal(|ui| {
        if !app.profiles.is_empty() {
            if ui.small_button("< Back").clicked() {
                app.view = View::ServerList;
            }
        }
        ui.label(egui::RichText::new("Login").size(14.0).strong().color(t.text));
    });
    ui.add_space(6.0);

    if app.login_in_progress {
        card(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                ui.spinner();
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Waiting for authentication...").size(14.0).color(t.text));
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Complete login in your browser").size(11.0).color(t.text_muted));
                ui.add_space(10.0);
            });
        });
        ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
        return;
    }

    if let Some(ref err) = app.login_error {
        ui.add_space(6.0);
        egui::Frame::default()
            .fill(egui::Color32::from_rgba_premultiplied(239, 68, 68, 25))
            .corner_radius(cr(10)).inner_margin(12.0)
            .show(ui, |ui| {
                ui.label(egui::RichText::new(err).size(12.0).color(t.danger));
            });
        ui.add_space(6.0);
    }

    card(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(10.0);
            draw_logo(ui);
            ui.add_space(8.0);
            let title = if app.profiles.is_empty() { "Sign in to NexGuard" } else { "Add Another Account" };
            ui.label(egui::RichText::new(title).size(16.0).strong().color(t.text));
            ui.add_space(4.0);
            let subtitle = if app.profiles.is_empty() {
                "Authenticate via browser to auto-configure your VPN"
            } else {
                "Each login creates a separate server profile"
            };
            ui.label(egui::RichText::new(subtitle).size(11.0).color(t.text_muted));
            ui.add_space(14.0);
            let btn = egui::Button::new(egui::RichText::new("Login with Browser").size(14.0).strong().color(t.text))
                .fill(t.accent)
                .min_size(egui::vec2(220.0, 42.0));
            if ui.add(btn).clicked() {
                app.start_login();
            }
            ui.add_space(10.0);
        });
    });

    ui.add_space(14.0);
    ui.separator();
    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new("Have a token?").size(12.0).color(t.text_muted));
        ui.add_space(4.0);
        if ui.add(egui::Button::new(egui::RichText::new("Add Manually").size(12.0).color(t.accent))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0_f32, t.accent))
            .min_size(egui::vec2(160.0, 32.0))).clicked() {
            app.view = View::AddServer;
        }
    });
}

fn draw_settings(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    ui.horizontal(|ui| {
        if ui.small_button("< Back").clicked() {
            app.view = View::ServerList;
        }
        ui.label(egui::RichText::new("Settings").size(14.0).strong().color(t.text));
    });
    ui.add_space(6.0);

    card(ui, |ui| {
        ui.label(egui::RichText::new("Connection").size(13.0).strong().color(t.text));
        ui.add_space(6.0);
        ui.label(lbl("Connection Mode"));
        ui.horizontal(|ui| {
            let modes = [("Auto", ConnectionMode::Auto), ("Direct UDP", ConnectionMode::DirectUdp), ("TLS Relay", ConnectionMode::TlsRelay)];
            for (label, mode) in modes {
                let selected = app.settings_connection_mode == mode;
                let fill = if selected { t.accent } else { t.surface };
                let txt_color = if selected { t.text } else { t.text_secondary };
                if ui.add(egui::Button::new(egui::RichText::new(label).size(11.0).color(txt_color))
                    .fill(fill)
                    .stroke(egui::Stroke::new(1.0_f32, if selected { t.accent } else { t.border }))
                    .min_size(egui::vec2(80.0, 28.0))).clicked() {
                    app.settings_connection_mode = mode;
                }
            }
        });
    });

    ui.add_space(6.0);
    card(ui, |ui| {
        ui.label(egui::RichText::new("General").size(13.0).strong().color(t.text));
        ui.add_space(6.0);
        if ui.checkbox(&mut app.settings_start_login, "Start NexGuard at login").changed() {
            if let Err(e) = crate::autostart::set_enabled(app.settings_start_login) {
                app.settings_start_login = crate::autostart::is_enabled();
                let _ = std::io::Write::write_fmt(
                    &mut std::io::stderr(),
                    format_args!("[autostart] failed: {}\n", e),
                );
            }
        }
    });

    ui.add_space(6.0);
    card(ui, |ui| {
        ui.label(egui::RichText::new("Security").size(13.0).strong().color(t.text));
        ui.add_space(6.0);
        ui.checkbox(&mut app.settings_kill_switch, "Kill switch (block traffic on disconnect)");
        ui.checkbox(&mut app.settings_dns_leak, "DNS leak protection (route DNS through tunnel)");
        ui.checkbox(&mut app.auto_reconnect, "Auto-reconnect on connection drop");
    });

    ui.add_space(6.0);
    card(ui, |ui| {
        ui.label(egui::RichText::new("Advanced").size(13.0).strong().color(t.text));
        ui.add_space(6.0);
        ui.label(lbl("Advertise Routes (comma-separated CIDRs)"));
        ui.add(egui::TextEdit::singleline(&mut app.settings_advertise_routes)
            .hint_text("e.g. 192.168.1.0/24, 10.0.0.0/8")
            .desired_width(f32::INFINITY)
            .margin(egui::vec2(10.0, 10.0)));
    });

    let mode_str = match app.settings_connection_mode {
        ConnectionMode::Auto => "auto",
        ConnectionMode::DirectUdp => "direct",
        ConnectionMode::TlsRelay => "tls",
    };
    let settings = crate::profiles::AppSettings {
        connection_mode: mode_str.to_string(),
        kill_switch: app.settings_kill_switch,
        dns_leak_protection: app.settings_dns_leak,
        advertise_routes: app.settings_advertise_routes.clone(),
        auto_reconnect: app.auto_reconnect,
    };
    crate::profiles::save_settings(&settings);
}

fn draw_connected(ui: &mut egui::Ui, status: &Option<VpnStatus>) {
    let t = theme();
    let Some(ref st) = status else { return; };
    let ip_only = st.address.split('/').next().unwrap_or(&st.address);
    let geo = st.geo.lock().unwrap().clone();

    card(ui, |ui| {
        ui.vertical_centered(|ui| {
            if let Some(ref g) = geo {
                ui.label(egui::RichText::new("Your IP").size(11.0).color(t.text_muted));
                ui.add_space(2.0);
                ui.label(egui::RichText::new(&g.ip).size(26.0).strong().color(t.success));
                let loc = if g.city.is_empty() { g.country.clone() } else { format!("{}, {}", g.city, g.country) };
                ui.label(egui::RichText::new(&loc).size(13.0).color(t.warning));
                if !g.isp.is_empty() {
                    ui.label(egui::RichText::new(&g.isp).size(10.0).color(t.text_muted));
                }
            } else {
                ui.label(egui::RichText::new("Your IP").size(11.0).color(t.text_muted));
                ui.add_space(2.0);
                ui.spinner();
                ui.label(egui::RichText::new("Detecting...").size(11.0).color(t.text_muted));
            }
        });
    });

    ui.add_space(6.0);
    let uptime = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs().saturating_sub(st.connected_at);
    ui.columns(4, |c| {
        mini_stat(&mut c[0], "TX", &fmt_bytes(st.tx.load(Ordering::Relaxed)), t.accent);
        mini_stat(&mut c[1], "RX", &fmt_bytes(st.rx.load(Ordering::Relaxed)), egui::Color32::from_rgb(168, 85, 247));
        mini_stat(&mut c[2], "Up", &fmt_uptime(uptime), t.success);
        mini_stat(&mut c[3], "Mode", if st.internet_mode { "Full" } else { "Split" }, egui::Color32::from_rgb(99, 102, 241));
    });

    ui.add_space(6.0);
    card(ui, |ui| {
        row(ui, "VPN IP", ip_only);
        if let Some(ref g) = geo {
            row(ui, "Public IP", &g.ip);
            if !g.region.is_empty() { row(ui, "Region", &g.region); }
        }
        row(ui, "Server", &st.server);
        row(ui, "Endpoint", &st.endpoint);
        row(ui, "Interface", &st.tun_name);
    });

    let peers = st.peers.lock().unwrap().clone();
    if !peers.is_empty() {
        ui.add_space(6.0);
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Devices").size(12.0).strong().color(t.text));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let direct = peers.iter().filter(|p| p.direct).count();
                    ui.label(
                        egui::RichText::new(format!("{} direct · {} relayed", direct, peers.len() - direct))
                            .size(10.0)
                            .color(t.text_muted),
                    );
                });
            });
            ui.add_space(4.0);
            for p in &peers {
                ui.horizontal(|ui| {
                    let (dot, tip) = if p.direct {
                        (t.success, "Direct peer-to-peer connection")
                    } else {
                        (t.text_muted, "Relayed through the server")
                    };
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 3.5, dot);
                    ui.label(egui::RichText::new(&p.name).size(12.0).color(t.text))
                        .on_hover_text(tip);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(&p.ip).size(11.0).color(t.text_secondary));
                    });
                });
            }
        });
    }
}

fn draw_update_banner(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    if let Some(ref result) = app.update_result.lock().unwrap().clone() {
        ui.add_space(8.0);
        let (msg, bg, tc) = match result {
            Ok(()) => ("Updated! Restart to apply.", egui::Color32::from_rgba_premultiplied(34, 197, 94, 20), t.success),
            Err(e) => (e.as_str(), egui::Color32::from_rgba_premultiplied(239, 68, 68, 20), t.danger),
        };
        egui::Frame::default().fill(bg).corner_radius(cr(12)).inner_margin(14.0)
            .show(ui, |ui| { ui.label(egui::RichText::new(msg).size(13.0).strong().color(tc)); });
        return;
    }
    if app.updating.load(Ordering::Relaxed) {
        ui.add_space(6.0);
        ui.horizontal(|ui| { ui.spinner(); ui.label(egui::RichText::new("Updating...").size(12.0).color(t.warning)); });
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        return;
    }
    let info = app.update_info.lock().unwrap().clone();
    if let Some(ref info) = info {
        if !info.has_update { return; }
        ui.add_space(8.0);
        egui::Frame::default()
            .fill(t.accent.linear_multiply(0.1))
            .corner_radius(cr(12))
            .inner_margin(14.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("v{} available", info.version))
                        .size(13.0).strong().color(t.text));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let url = info.download_url.clone();
                        let btn = egui::Button::new(
                            egui::RichText::new("Update").size(12.0).color(t.text),
                        ).fill(t.accent).min_size(egui::vec2(80.0, 30.0));
                        if ui.add(btn).clicked() { app.start_update(url); }
                    });
                });
            });
    }
}

fn mini_stat(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32) {
    let t = theme();
    egui::Frame::default().fill(t.surface).corner_radius(cr(10)).inner_margin(10.0)
        .stroke(egui::Stroke::new(1.0_f32, t.border))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).size(10.0).color(t.text_muted));
            ui.label(egui::RichText::new(value).size(14.0).strong().color(color));
        });
}

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    let t = theme();
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(label).size(12.0).color(t.text_muted));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(value).size(12.0).color(t.text_secondary));
        });
    });
    ui.add_space(2.0);
}

fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1024; const MB: u64 = 1024 * 1024; const GB: u64 = 1024 * 1024 * 1024;
    if b < KB { format!("{} B", b) } else if b < MB { format!("{:.1} KB", b as f64 / KB as f64) }
    else if b < GB { format!("{:.1} MB", b as f64 / MB as f64) } else { format!("{:.1} GB", b as f64 / GB as f64) }
}

fn fmt_uptime(s: u64) -> String {
    if s < 60 { format!("{}s", s) } else if s < 3600 { format!("{}m{}s", s / 60, s % 60) }
    else { format!("{}h{}m", s / 3600, (s % 3600) / 60) }
}

fn logo_texture(ctx: &egui::Context) -> egui::TextureHandle {
    ctx.data(|d| d.get_temp::<egui::TextureHandle>(egui::Id::new("ng_logo"))).unwrap_or_else(|| {
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

fn draw_logo(ui: &mut egui::Ui) {
    let tex = logo_texture(ui.ctx());
    let size = 40.0;
    ui.add(egui::Image::new(&tex).fit_to_exact_size(egui::vec2(size, size)));
}

fn generate_app_icon() -> egui::IconData {
    let png = include_bytes!("../assets/logo-128.png");
    let img = image::load_from_memory(png).unwrap().to_rgba8();
    egui::IconData { width: img.width(), height: img.height(), rgba: img.into_raw() }
}
