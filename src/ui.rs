use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::profiles::ServerProfile;
use crate::vpn::{ConnectionState, VpnConfig, VpnStatus};

enum View { ServerList, AddServer }

struct VpnApp {
    profiles: Vec<ServerProfile>,
    selected: Option<usize>,
    view: View,
    new_name: String,
    new_server: String,
    new_token: String,
    new_internet: bool,
    new_share_lan: bool,
    new_kill_switch: bool,
    show_token: bool,
    state: Arc<Mutex<ConnectionState>>,
    status: Arc<Mutex<Option<VpnStatus>>>,
    last_error: Arc<Mutex<Option<String>>>,
    shutdown: Arc<AtomicBool>,
    kill_switch: Arc<AtomicBool>,
    session: Option<std::thread::JoinHandle<()>>,
    session_running: Arc<AtomicBool>,
    session_token: Option<String>,
    pending_connect: bool,
    pending_quit: bool,
    quit_deadline: Option<std::time::Instant>,
    window_visible: bool,
    connect_trigger: Arc<AtomicBool>,
    selected_server: Arc<AtomicUsize>,
    tray: Option<crate::tray::NexTray>,
    update_info: Arc<Mutex<Option<crate::api::UpdateInfo>>>,
    updating: Arc<AtomicBool>,
    update_result: Arc<Mutex<Option<Result<(), String>>>>,
    confirm_delete: Option<usize>,
    confirm_logout: bool,
    editing_idx: Option<usize>,
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
        Self {
            selected: if profiles.is_empty() { None } else { Some(0) },
            profiles,
            view: View::ServerList,
            new_name: String::new(),
            new_server: String::new(),
            new_token: String::new(),
            new_internet: true,
            new_share_lan: false,
            new_kill_switch: false,
            show_token: false,
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            status: Arc::new(Mutex::new(None)),
            last_error: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(AtomicBool::new(false)),
            kill_switch: Arc::new(AtomicBool::new(false)),
            session: None,
            session_running: Arc::new(AtomicBool::new(false)),
            session_token: None,
            pending_connect: false,
            pending_quit: false,
            quit_deadline: None,
            window_visible: true,
            connect_trigger: Arc::new(AtomicBool::new(false)),
            selected_server: Arc::new(AtomicUsize::new(usize::MAX)),
            tray: None,
            update_info,
            updating: Arc::new(AtomicBool::new(false)),
            update_result: Arc::new(Mutex::new(None)),
            confirm_delete: None,
            confirm_logout: false,
            editing_idx: None,
        }
    }
}

fn resolve_config(profile: &ServerProfile, kill_switch: Arc<AtomicBool>) -> Result<VpnConfig, String> {
    let mut server = profile.server.clone();
    let mut relay: Option<String> = None;
    let mut relay_name: Option<String> = None;
    let mut join_url: Option<String> = None;

    let cached = if profile.token.is_empty() {
        None
    } else {
        crate::cache::load(&profile.token)
    };

    if server.is_empty() && !profile.token.is_empty() {
        if let Some(ref c) = cached {
            server = c.server.clone().unwrap_or_default();
            relay = c.relay.clone();
            relay_name = c.relay_name.clone();
            join_url = c.join_url.clone();
            if server.is_empty() && relay.is_some() {
                server = RELAY_SERVER_NAME.to_string();
            }
        } else {
            let info = crate::api::fetch_connect_info(&profile.token)
                .ok_or(ERR_API_UNREACHABLE)?;
            join_url = info.join_url.clone();
            if let Some(s) = info.server.clone() {
                server = s;
            } else if let Some(r) = info.relay.clone() {
                relay = Some(r);
                relay_name = info.relay_name.clone();
                server = RELAY_SERVER_NAME.to_string();
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
    }

    if server.is_empty() && join_url.is_none() {
        return Err(ERR_SERVER_NOT_FOUND.to_string());
    }
    if server.is_empty() {
        server = API_PROXY_SERVER_NAME.to_string();
    }

    kill_switch.store(profile.kill_switch, Ordering::Relaxed);

    Ok(VpnConfig {
        server,
        token: profile.token.clone(),
        internet: profile.internet,
        share_lan: profile.share_lan,
        kill_switch,
        relay,
        relay_name,
        join_url,
        ..VpnConfig::default()
    })
}

impl VpnApp {
    fn session_live(&self) -> bool {
        self.session_running.load(Ordering::Relaxed)
    }

    fn reap_session(&mut self) {
        if !self.session_live() {
            if let Some(handle) = self.session.take() {
                let _ = handle.join();
            }
        }
    }

    fn connect_selected(&mut self) {
        let Some(idx) = self.selected else { return };
        let Some(profile) = self.profiles.get(idx) else { return };
        let profile = profile.clone();

        if self.session_live() {
            self.disconnect();
            self.pending_connect = true;
            return;
        }
        self.reap_session();

        self.shutdown.store(false, Ordering::Relaxed);
        self.session_token = Some(profile.token.clone());
        *self.last_error.lock().unwrap() = None;
        *self.state.lock().unwrap() = ConnectionState::Connecting;
        self.session_running.store(true, Ordering::Relaxed);

        let state = Arc::clone(&self.state);
        let status_slot = Arc::clone(&self.status);
        let shutdown = Arc::clone(&self.shutdown);
        let last_error = Arc::clone(&self.last_error);
        let kill_switch = Arc::clone(&self.kill_switch);
        let running = Arc::clone(&self.session_running);
        self.session = Some(std::thread::spawn(move || {
            match resolve_config(&profile, kill_switch) {
                Ok(config) => crate::vpn::run_session(
                    config,
                    shutdown,
                    Arc::clone(&state),
                    status_slot,
                    Arc::clone(&last_error),
                ),
                Err(msg) => {
                    *last_error.lock().unwrap() = Some(msg.clone());
                    *state.lock().unwrap() = ConnectionState::Error(msg);
                }
            }
            running.store(false, Ordering::Relaxed);
        }));
    }

    fn disconnect(&mut self) {
        self.pending_connect = false;
        self.shutdown.store(true, Ordering::Relaxed);
    }

    fn begin_quit(&mut self) {
        self.disconnect();
        self.pending_quit = true;
        self.quit_deadline = Some(std::time::Instant::now() + QUIT_GRACE);
    }

    fn save_new_server(&mut self) {
        let name = if self.new_name.is_empty() { "VPN Server".to_string() } else { self.new_name.clone() };
        let profile = ServerProfile {
            name,
            server: self.new_server.clone(),
            token: self.new_token.clone(),
            internet: self.new_internet,
            share_lan: self.new_share_lan,
            kill_switch: self.new_kill_switch,
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
        self.new_kill_switch = false;
        self.view = View::ServerList;
    }

    fn start_edit(&mut self, idx: usize) {
        if let Some(p) = self.profiles.get(idx) {
            self.new_name = p.name.clone();
            self.new_server = p.server.clone();
            self.new_token = p.token.clone();
            self.new_internet = p.internet;
            self.new_share_lan = p.share_lan;
            self.new_kill_switch = p.kill_switch;
            self.editing_idx = Some(idx);
            self.view = View::AddServer;
        }
    }

    fn remove_selected(&mut self) {
        if let Some(idx) = self.selected {
            if self.is_session_profile(idx) {
                self.disconnect();
            }
            crate::profiles::remove(&mut self.profiles, idx);
            self.selected = if self.profiles.is_empty() { None } else { Some(0) };
            self.sync_tray_servers();
        }
    }

    fn is_session_profile(&self, idx: usize) -> bool {
        self.session_live()
            && self.session_token.is_some()
            && self.profiles.get(idx).map(|p| &p.token) == self.session_token.as_ref()
    }

    fn log_out(&mut self) {
        if self.session_live() {
            self.disconnect();
        }
        crate::profiles::clear_all(&mut self.profiles);
        self.session_token = None;
        self.selected = None;
        self.sync_tray_servers();
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
}

const APP_NAME: &str = "NexGuard VPN";
const RELAY_SERVER_NAME: &str = "relay";
const API_PROXY_SERVER_NAME: &str = "api-proxy";
const ERR_API_UNREACHABLE: &str = "Cannot reach NexGuard API. Check your internet connection.";
const ERR_SERVER_NOT_FOUND: &str = "Server not found. Check your token.";
const PANIC_LOG_FILE: &str = "panic.log";
const DEPLOY_URL: &str = "https://nexguard.sh/deploy";
const DNS_UNPROTECTED_WARNING: &str =
    "DNS is not protected — the server sent no resolver, so lookups still use your local network. Set NEXGUARD_DNS to route them through the tunnel.";
const KILL_SWITCH_LABEL: &str = "Kill switch — block traffic if VPN drops";
const KILL_SWITCH_HINT: &str = "Takes effect on the next connection attempt.";
const QUIT_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
const REPAINT_ACTIVE_MS: u64 = 200;
const REPAINT_IDLE_MS: u64 = 500;
const REPAINT_HIDDEN_MS: u64 = 1000;

#[cfg(unix)]
extern "C" fn gui_handle_signal(_: libc::c_int) {
    crate::route::cleanup_active_tuns();
    std::process::exit(0);
}

fn record_panic(info: &std::panic::PanicHookInfo<'_>) {
    use std::io::Write;
    let location = info.location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "unknown".to_string());
    let message = format!(
        "[nexguard] v{} PANIC at {}: {}",
        env!("CARGO_PKG_VERSION"),
        location,
        info,
    );
    let _ = writeln!(std::io::stderr(), "{}", message);
    if let Some(path) = crate::dirs_next().map(|d| d.join(PANIC_LOG_FILE)) {
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(file, "{}", message);
        }
    }
}

fn install_cleanup_handlers() {
    std::panic::set_hook(Box::new(|info| {
        record_panic(info);
        crate::route::cleanup_active_tuns();
    }));
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, gui_handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, gui_handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, gui_handle_signal as *const () as libc::sighandler_t);
    }
}

pub fn run_gui_with(token: Option<String>, name: Option<String>, internet: bool) {
    install_cleanup_handlers();
    let icon = generate_app_icon();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 620.0])
            .with_min_inner_size([400.0, 560.0])
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
            Arc::clone(&app.state),
            Arc::clone(&app.shutdown),
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
                internet,
                share_lan: false,
                kill_switch: false,
            };
            crate::profiles::add(&mut app.profiles, profile);
            app.selected = Some(app.profiles.len() - 1);
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
    #[allow(dead_code)]
    accent_hover: egui::Color32,
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
        accent_hover: egui::Color32::from_rgb(125, 211, 252),
        success: egui::Color32::from_rgb(56, 189, 248),
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
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, t.border);
    style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, t.text_secondary);
    style.visuals.widgets.hovered.bg_fill = t.surface_hover;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.5, t.border_active);
    style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, t.text);
    style.visuals.widgets.active.bg_fill = t.surface_hover;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.5, t.accent);
    style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, t.text);
    style.visuals.widgets.noninteractive.bg_fill = t.surface;
    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, t.text_secondary);
    style.visuals.extreme_bg_color = t.input_bg;
    style.visuals.panel_fill = t.bg;
    style.visuals.window_fill = t.bg;
    style.visuals.selection.bg_fill = t.accent.linear_multiply(0.3);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, t.accent);

    ctx.set_style(style);
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    let t = theme();
    egui::Frame::default()
        .fill(t.surface)
        .corner_radius(cr(12))
        .inner_margin(16.0)
        .stroke(egui::Stroke::new(1.0, t.border))
        .show(ui, add);
}

fn lbl(t: &str) -> egui::RichText {
    egui::RichText::new(t).size(12.0).color(theme().text_muted)
}

fn read_clipboard() -> Option<String> {
    arboard::Clipboard::new().ok()?.get_text().ok()
}

impl eframe::App for VpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| i.viewport().close_requested()) {
            let quit = self.pending_quit
                || self.tray.is_none()
                || self.tray.as_ref().is_some_and(|t| t.quit_requested);
            if quit {
                self.begin_quit();
                if self.session_live() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                }
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(egui::WindowLevel::Normal));
                self.window_visible = false;
            }
        }

        let state = self.state.lock().unwrap().clone();
        let status = self.status.lock().unwrap().clone();

        let mut quit_requested = false;
        let mut show_requested = false;
        let mut reconnect_requested = false;
        if let Some(ref mut tray) = self.tray {
            tray.tick();
            quit_requested = tray.quit_requested;
            show_requested = std::mem::take(&mut tray.show_requested);
            if tray.reconnect_after_disconnect
                && matches!(state, ConnectionState::Disconnected | ConnectionState::Error(_))
            {
                tray.reconnect_after_disconnect = false;
                reconnect_requested = true;
            }
        }

        if quit_requested {
            self.begin_quit();
        }
        if show_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            self.window_visible = true;
        }
        if ctx.input(|i| i.viewport().focused.unwrap_or(false)) {
            self.window_visible = true;
        }
        if reconnect_requested {
            self.connect_selected();
        }

        if self.window_visible {
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
            match state {
                ConnectionState::Connected | ConnectionState::Degraded => {
                    let degraded = matches!(state, ConnectionState::Degraded);
                    draw_header_connected(ui, self, degraded);
                    ui.add_space(6.0);
                    draw_connected(ui, &status);
                    ui.add_space(6.0);
                    draw_killswitch_toggle(ui, self);
                    ui.add_space(6.0);
                    draw_server_view(ui, self);
                    ctx.request_repaint_after(std::time::Duration::from_millis(REPAINT_ACTIVE_MS));
                }
                ConnectionState::Connecting | ConnectionState::Handshaking | ConnectionState::Reconnecting => {
                    let t = theme();
                    draw_header(ui);
                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        ui.spinner();
                        ui.add_space(4.0);
                        let is_disconnecting = self.shutdown.load(Ordering::Relaxed);
                        let msg = if is_disconnecting {
                            "Disconnecting..."
                        } else {
                            match state {
                                ConnectionState::Handshaking => "Handshaking...",
                                ConnectionState::Reconnecting => "Reconnecting...",
                                _ => "Connecting...",
                            }
                        };
                        ui.label(egui::RichText::new(msg).size(14.0).color(t.warning));
                        if let Some(ref last) = self.last_error.lock().unwrap().clone() {
                            ui.label(egui::RichText::new(last).size(11.0).color(t.danger));
                        }
                    });
                    ui.add_space(6.0);
                    draw_server_view(ui, self);
                    ctx.request_repaint_after(std::time::Duration::from_millis(REPAINT_ACTIVE_MS));
                }
                ConnectionState::Error(ref msg) => {
                    let t = theme();
                    draw_header(ui);
                    draw_server_view(ui, self);
                    ui.add_space(6.0);
                    egui::Frame::default()
                        .fill(egui::Color32::from_rgba_premultiplied(239, 68, 68, 25))
                        .corner_radius(cr(10)).inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(msg).size(12.0).color(t.danger));
                        });
                }
                ConnectionState::Disconnected => {
                    draw_header(ui);
                    draw_server_view(ui, self);
                }
            }
            draw_update_banner(ui, self);
            });
        });
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
            if state_is_active(&state) {
                self.disconnect();
                if let Some(ref mut tray) = self.tray {
                    tray.reconnect_after_disconnect = true;
                }
            } else {
                self.connect_selected();
            }
        }

        if self.pending_connect && !self.session_live() {
            self.pending_connect = false;
            self.connect_selected();
        }
        self.reap_session();

        if self.pending_quit {
            let expired = self.quit_deadline.is_some_and(|d| std::time::Instant::now() >= d);
            if !self.session_live() || expired {
                if expired && self.session_live() {
                    crate::route::cleanup_active_tuns();
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(REPAINT_ACTIVE_MS));
            return;
        }

        let repaint_interval = if !self.window_visible {
            REPAINT_HIDDEN_MS
        } else if state_is_active(&state) {
            REPAINT_ACTIVE_MS
        } else {
            REPAINT_IDLE_MS
        };
        ctx.request_repaint_after(std::time::Duration::from_millis(repaint_interval));
    }
}

fn state_is_active(s: &ConnectionState) -> bool {
    !matches!(s, ConnectionState::Disconnected | ConnectionState::Error(_))
}

fn draw_killswitch_toggle(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    let Some(idx) = app.selected else { return };
    let mut ks = app.profiles.get(idx).map(|p| p.kill_switch).unwrap_or(false);
    card(ui, |ui| {
        if ui.checkbox(&mut ks, KILL_SWITCH_LABEL).changed() {
            if let Some(p) = app.profiles.get_mut(idx) {
                p.kill_switch = ks;
            }
            crate::profiles::save(&app.profiles);
            if app.is_session_profile(idx) {
                app.kill_switch.store(ks, Ordering::Relaxed);
            }
        }
        ui.label(egui::RichText::new(KILL_SWITCH_HINT).size(10.0).color(t.text_muted));
    });
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

fn draw_header_connected(ui: &mut egui::Ui, app: &mut VpnApp, degraded: bool) {
    let t = theme();
    let (dot_color, label, label_color) = if degraded {
        (t.warning, "Degraded — traffic protected, reconnecting link", t.warning)
    } else {
        (t.success, "Connected", t.success)
    };
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
                ui.label(egui::RichText::new("●").size(12.0).color(dot_color));
                ui.label(egui::RichText::new(label).size(12.0).strong().color(label_color));
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
    }
}

fn draw_server_list(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Servers").size(14.0).strong().color(t.text));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(egui::Button::new(egui::RichText::new("+ Add").size(12.0).color(t.accent)).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::new(1.0, t.accent))).clicked() {
                app.view = View::AddServer;
            }
            if !app.profiles.is_empty()
                && ui.add(egui::Button::new(egui::RichText::new("Log out").size(11.0).color(t.text_muted)).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE)).clicked() {
                app.confirm_logout = true;
            }
            if ui.add(egui::Button::new(egui::RichText::new("Deploy server ↗").size(11.0).color(t.accent)).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE)).clicked() {
                let _ = open::that(DEPLOY_URL);
            }
        });
    });
    ui.add_space(6.0);

    if app.profiles.is_empty() {
        draw_add_server(ui, app);
        return;
    } else {
        let mut connect_idx: Option<usize> = None;
        let mut edit_idx: Option<usize> = None;
        let mut select_idx: Option<usize> = None;
        let mut disconnect_now = false;
        let current_state = app.state.lock().unwrap().clone();
        let is_connected = state_is_active(&current_state);
        let session_live = app.session_live();
        for (i, profile) in app.profiles.iter().enumerate() {
            let is_selected = app.selected == Some(i);
            let fill = if is_selected { t.surface_hover } else { t.surface };
            let stroke_color = if is_selected { t.accent } else { t.border };

            let card = egui::Frame::default()
                .fill(fill)
                .corner_radius(cr(10))
                .inner_margin(12.0)
                .stroke(egui::Stroke::new(if is_selected { 1.5 } else { 1.0 }, stroke_color))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let dot = if is_selected { "●" } else { "○" };
                        let dot_color = if is_selected { t.accent } else { t.text_muted };
                        ui.label(egui::RichText::new(dot).size(12.0).color(dot_color));
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(&profile.name).size(13.0).strong().color(t.text));
                            let desc = if profile.server.is_empty() { "Token-based" } else { &profile.server };
                            ui.label(egui::RichText::new(desc).size(11.0).color(t.text_muted));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let (menu_rect, menu_resp_raw) = ui.allocate_exact_size(
                                egui::vec2(24.0, 28.0), egui::Sense::click()
                            );
                            let dot_color = if menu_resp_raw.hovered() { t.text } else { t.text_muted };
                            let cx = menu_rect.center().x;
                            let cy = menu_rect.center().y;
                            for (i, dy) in [-7.0, 0.0, 7.0].iter().enumerate() {
                                let _ = i;
                                ui.painter().circle_filled(
                                    egui::pos2(cx, cy + dy),
                                    1.8,
                                    dot_color,
                                );
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

                            ui.add_space(4.0);
                            let active = is_connected && app.selected == Some(i);
                            let (label, fill_color) = if active {
                                ("Disconnect", t.danger)
                            } else {
                                ("Connect", t.accent)
                            };
                            let action_btn = egui::Button::new(
                                egui::RichText::new(label).size(11.0).color(t.text)
                            )
                            .fill(fill_color)
                            .min_size(egui::vec2(82.0, 24.0));
                            let enabled = active || !session_live;
                            if ui.add_enabled(enabled, action_btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                if active {
                                    disconnect_now = true;
                                } else {
                                    connect_idx = Some(i);
                                }
                            }
                        });
                    });
                });

            let card_rect = card.response.rect;
            const RIGHT_AREA: f32 = 140.0;
            let click_rect = egui::Rect::from_min_max(
                card_rect.min,
                egui::pos2((card_rect.max.x - RIGHT_AREA).max(card_rect.min.x), card_rect.max.y),
            );
            let card_id = egui::Id::new(("server_card_select", i));
            if ui.interact(click_rect, card_id, egui::Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                select_idx = Some(i);
            }

            ui.add_space(3.0);
        }

        if disconnect_now {
            app.disconnect();
        } else if let Some(idx) = edit_idx {
            app.start_edit(idx);
        } else if let Some(idx) = connect_idx {
            app.selected = Some(idx);
            app.connect_selected();
        } else if let Some(idx) = select_idx {
            app.selected = Some(idx);
            app.sync_tray_servers();
        }
    }

    if let Some(idx) = ui.ctx().data(|d| d.get_temp::<usize>(egui::Id::new("del_confirm_idx"))) {
        ui.ctx().data_mut(|d| d.remove_temp::<usize>(egui::Id::new("del_confirm_idx")));
        ui.ctx().data_mut(|d| d.remove_temp::<usize>(egui::Id::new("sel_idx")));
        app.confirm_delete = Some(idx);
    }
    if let Some(sel) = ui.ctx().data(|d| d.get_temp::<usize>(egui::Id::new("sel_idx"))) {
        ui.ctx().data_mut(|d| d.remove_temp::<usize>(egui::Id::new("sel_idx")));
        if app.confirm_delete.is_none() {
            app.selected = Some(sel);
        }
    }

    if let Some(idx) = app.confirm_delete {
        let name = app.profiles.get(idx).map(|p| p.name.clone()).unwrap_or_default();
        match confirm_dialog(
            ui.ctx(),
            "Confirm deletion",
            &format!("Remove \"{}\"?", name),
            "This only removes it from this device.",
            "Delete",
        ) {
            Some(true) => {
                app.selected = Some(idx);
                app.remove_selected();
                app.confirm_delete = None;
            }
            Some(false) => app.confirm_delete = None,
            None => {}
        }
    }

    if app.confirm_logout {
        match confirm_dialog(
            ui.ctx(),
            "Confirm log out",
            "Log out of NexGuard?",
            "This removes every saved server and cached credential from this device.",
            "Log out",
        ) {
            Some(true) => {
                app.log_out();
                app.confirm_logout = false;
            }
            Some(false) => app.confirm_logout = false,
            None => {}
        }
    }

}

fn confirm_dialog(
    ctx: &egui::Context,
    title: &str,
    question: &str,
    detail: &str,
    action: &str,
) -> Option<bool> {
    let t = theme();
    let mut answer = None;
    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .fixed_size(egui::vec2(280.0, 120.0))
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(6.0);
                ui.label(egui::RichText::new(question).size(13.0).color(t.text));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(detail).size(11.0).color(t.text_muted));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.add_space(30.0);
                    if ui.add(egui::Button::new(egui::RichText::new("Cancel").size(12.0).color(t.text))
                        .fill(t.surface).min_size(egui::vec2(90.0, 28.0))).clicked() {
                        answer = Some(false);
                    }
                    ui.add_space(8.0);
                    if ui.add(egui::Button::new(egui::RichText::new(action).size(12.0).color(egui::Color32::WHITE))
                        .fill(t.danger).min_size(egui::vec2(90.0, 28.0))).clicked() {
                        answer = Some(true);
                    }
                });
            });
        });
    answer
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
            app.new_kill_switch = false;
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
        ui.checkbox(&mut app.new_kill_switch, "Kill switch — block traffic if VPN drops");
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
            .stroke(egui::Stroke::new(1.0, t.accent))
            .min_size(egui::vec2(200.0, 36.0))).clicked() {
            let _ = open::that(DEPLOY_URL);
        }
    });
}

fn draw_connected(ui: &mut egui::Ui, status: &Option<VpnStatus>) {
    let t = theme();
    let Some(ref st) = status else { return };
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
            } else if st.geo_failed.load(Ordering::Relaxed) {
                ui.label(egui::RichText::new("Your IP").size(11.0).color(t.text_muted));
                ui.add_space(2.0);
                ui.label(egui::RichText::new("IP unavailable").size(14.0).color(t.text_muted));
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

    if st.internet_mode && !st.dns_protected {
        ui.add_space(6.0);
        egui::Frame::default()
            .fill(egui::Color32::from_rgba_premultiplied(234, 179, 8, 25))
            .corner_radius(cr(10))
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.label(egui::RichText::new(DNS_UNPROTECTED_WARNING).size(11.0).color(t.warning));
            });
    }

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
        .stroke(egui::Stroke::new(1.0, t.border))
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
