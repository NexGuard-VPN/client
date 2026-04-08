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

enum View { ServerList, AddServer }

struct VpnApp {
    profiles: Vec<ServerProfile>,
    selected: Option<usize>,
    view: View,
    new_name: String,
    new_server: String,
    new_token: String,
    new_internet: bool,
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
            show_token: false,
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            status: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(AtomicBool::new(false)),
            connect_trigger: Arc::new(AtomicBool::new(false)),
            selected_server: Arc::new(AtomicUsize::new(0)),
            tray: None,
            update_info,
            updating: Arc::new(AtomicBool::new(false)),
            update_result: Arc::new(Mutex::new(None)),
        }
    }
}

impl VpnApp {
    fn connect_selected(&mut self) {
        let Some(idx) = self.selected else { return };
        let Some(profile) = self.profiles.get(idx) else { return };
        let profile = profile.clone();
        self.shutdown = Arc::new(AtomicBool::new(false));
        *self.state.lock().unwrap() = ConnectionState::Connecting;
        let state = Arc::clone(&self.state);
        let status_slot = Arc::clone(&self.status);
        let shutdown = Arc::clone(&self.shutdown);
        std::thread::spawn(move || {
            let mut server = profile.server.clone();
            let mut relay: Option<String> = None;
            let mut relay_name: Option<String> = None;
            let mut join_url: Option<String> = None;

            if server.is_empty() && !profile.token.is_empty() {
                if let Some(info) = crate::api::fetch_connect_info(&profile.token) {
                    join_url = info.join_url;
                    if let Some(s) = info.server {
                        server = s;
                    } else if let Some(r) = info.relay {
                        relay = Some(r.clone());
                        relay_name = info.relay_name;
                        server = r.split(':').next().unwrap_or(&r).to_string();
                    }
                }
            }

            if server.is_empty() && join_url.is_none() {
                *state.lock().unwrap() = ConnectionState::Error("Could not resolve server".into());
                return;
            }
            if server.is_empty() { server = "api-proxy".to_string(); }

            let config = VpnConfig {
                server,
                token: profile.token.clone(),
                internet: profile.internet,
                relay,
                relay_name,
                join_url,
                ..VpnConfig::default()
            };
            match crate::vpn::connect(config, Arc::clone(&shutdown)) {
                Ok(st) => {
                    let geo_slot = Arc::clone(&st.geo);
                    *status_slot.lock().unwrap() = Some(st);
                    *state.lock().unwrap() = ConnectionState::Connected;
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        if let Some(info) = crate::api::fetch_geo_info() {
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
            std::thread::sleep(std::time::Duration::from_millis(1500));
            if let Some(status) = status_slot.lock().unwrap().take() {
                if status.internet_mode {
                    crate::route::emergency_cleanup(&status.tun_name);
                }
            }
            *state.lock().unwrap() = ConnectionState::Disconnected;
        });
    }

    fn save_new_server(&mut self) {
        let name = if self.new_name.is_empty() { "VPN Server".to_string() } else { self.new_name.clone() };
        let profile = ServerProfile {
            name,
            server: self.new_server.clone(),
            token: self.new_token.clone(),
            internet: self.new_internet,
        };
        crate::profiles::add(&mut self.profiles, profile);
        self.selected = Some(self.profiles.len() - 1);
        self.sync_tray_servers();
        self.new_name.clear();
        self.new_server.clear();
        self.new_token.clear();
        self.new_internet = true;
        self.view = View::ServerList;
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
}

const APP_NAME: &str = "NexGuard VPN";

pub fn run_gui_with(token: Option<String>, name: Option<String>, internet: bool) {
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

        app.tray = crate::tray::NexTray::new(
            Arc::clone(&app.status),
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
    style.spacing.button_padding = egui::vec2(16.0, 8.0);
    style.spacing.text_edit_width = 400.0;
    style.spacing.interact_size.y = 36.0;
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

impl eframe::App for VpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let quit = self.tray.as_ref().map_or(false, |t| t.quit_requested);
        if ctx.input(|i| i.viewport().close_requested()) && !quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
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

        if let Some(ref mut tray) = self.tray {
            tray.tick();

            if tray.quit_requested {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }

            if tray.reconnect_after_disconnect && matches!(state, ConnectionState::Disconnected | ConnectionState::Error(_)) {
                tray.reconnect_after_disconnect = false;
                self.connect_selected();
            }
        }

        let tray_server = self.selected_server.load(Ordering::Relaxed);
        if tray_server != self.selected.unwrap_or(usize::MAX) {
            if tray_server < self.profiles.len() {
                self.selected = Some(tray_server);
                self.sync_tray_servers();
            }
        }

        if self.connect_trigger.swap(false, Ordering::Relaxed) {
            if matches!(state, ConnectionState::Disconnected | ConnectionState::Error(_)) {
                self.connect_selected();
            }
        }

        if matches!(state, ConnectionState::Connected | ConnectionState::Connecting) {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
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
                ui.label(egui::RichText::new("●").size(12.0).color(t.success));
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
        });
    });
    ui.add_space(6.0);

    if app.profiles.is_empty() {
        draw_add_server(ui, app);
        return;
    } else {
        for (i, profile) in app.profiles.iter().enumerate() {
            let is_selected = app.selected == Some(i);
            let fill = if is_selected { t.surface_hover } else { t.surface };
            let stroke_color = if is_selected { t.accent } else { t.border };

            let frame_resp = egui::Frame::default()
                .fill(fill)
                .corner_radius(cr(12))
                .inner_margin(14.0)
                .stroke(egui::Stroke::new(if is_selected { 1.5 } else { 1.0 }, stroke_color))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let radio_icon = if is_selected { "◉" } else { "○" };
                        let radio_color = if is_selected { t.accent } else { t.text_muted };
                        ui.label(egui::RichText::new(radio_icon).size(14.0).color(radio_color));
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(&profile.name).size(13.0).strong().color(t.text));
                            let desc = if profile.server.is_empty() { "Token-based" } else { &profile.server };
                            ui.label(egui::RichText::new(desc).size(11.0).color(t.text_muted));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let del_btn = ui.add(egui::Button::new(
                                egui::RichText::new("🗑").size(14.0)
                            ).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE));
                            if del_btn.clicked() {
                                ui.ctx().data_mut(|d| d.insert_temp(egui::Id::new("del_idx"), i));
                            }
                        });
                    });
                });

            let card_rect = frame_resp.response.rect;
            let card_resp = ui.interact(card_rect, egui::Id::new(format!("server_card_{}", i)), egui::Sense::click());
            if card_resp.clicked() && !is_selected {
                ui.ctx().data_mut(|d| d.insert_temp(egui::Id::new("sel_idx"), i));
            }

            ui.add_space(3.0);
        }
    }

    if let Some(del) = ui.ctx().data(|d| d.get_temp::<usize>(egui::Id::new("del_idx"))) {
        ui.ctx().data_mut(|d| d.remove_temp::<usize>(egui::Id::new("del_idx")));
        app.selected = Some(del);
        app.remove_selected();
    }
    if let Some(sel) = ui.ctx().data(|d| d.get_temp::<usize>(egui::Id::new("sel_idx"))) {
        ui.ctx().data_mut(|d| d.remove_temp::<usize>(egui::Id::new("sel_idx")));
        app.selected = Some(sel);
    }

    let t = theme();
    let current_state = app.state.lock().unwrap().clone();
    let is_connected = matches!(current_state, ConnectionState::Connected);
    let is_connecting = matches!(current_state, ConnectionState::Connecting);

    if !is_connected && !is_connecting {
        ui.add_space(10.0);
        ui.vertical_centered(|ui| {
            let can_connect = app.selected.is_some() && !app.profiles.is_empty();
            let btn = egui::Button::new(egui::RichText::new("Connect").size(14.0).strong().color(t.text))
                .fill(if can_connect { t.accent } else { t.surface_hover })
                .min_size(egui::vec2(200.0, 40.0));
            if ui.add_enabled(can_connect, btn).clicked() {
                app.connect_selected();
            }
        });
    }
}

fn draw_add_server(ui: &mut egui::Ui, app: &mut VpnApp) {
    let t = theme();
    ui.horizontal(|ui| {
        if ui.small_button("< Back").clicked() {
            app.view = View::ServerList;
        }
        ui.label(egui::RichText::new("Add Server").size(14.0).strong().color(t.text));
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
            });
        });
        ui.add(egui::TextEdit::singleline(&mut app.new_token).password(!app.show_token).hint_text("Paste token from dashboard").desired_width(f32::INFINITY).margin(egui::vec2(10.0, 10.0)));

        ui.add_space(8.0);
        ui.checkbox(&mut app.new_internet, "Route all traffic through VPN");
    });

    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        let ok = !app.new_token.is_empty();
        let btn = egui::Button::new(egui::RichText::new("Save & Connect").size(14.0).strong().color(t.text))
            .fill(if ok { t.accent } else { t.surface_hover })
            .min_size(egui::vec2(200.0, 40.0));
        if ui.add_enabled(ok, btn).clicked() {
            app.save_new_server();
            app.connect_selected();
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
            let _ = open::that("https://nexguard.sh/deploy");
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
