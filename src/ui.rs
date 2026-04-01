use std::sync::atomic::{AtomicBool, Ordering};
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
        let config = VpnConfig {
            server: profile.server.clone(),
            token: profile.token.clone(),
            internet: profile.internet,
            ..VpnConfig::default()
        };
        self.shutdown = Arc::new(AtomicBool::new(false));
        *self.state.lock().unwrap() = ConnectionState::Connecting;
        let state = Arc::clone(&self.state);
        let status_slot = Arc::clone(&self.status);
        let shutdown = Arc::clone(&self.shutdown);
        std::thread::spawn(move || {
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
        std::thread::sleep(std::time::Duration::from_millis(500));
        *self.state.lock().unwrap() = ConnectionState::Disconnected;
        *self.status.lock().unwrap() = None;
    }

    fn save_new_server(&mut self) {
        let profile = ServerProfile {
            name: if self.new_name.is_empty() { self.new_server.clone() } else { self.new_name.clone() },
            server: self.new_server.clone(),
            token: self.new_token.clone(),
            internet: self.new_internet,
        };
        crate::profiles::add(&mut self.profiles, profile);
        self.selected = Some(self.profiles.len() - 1);
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

pub fn run_gui() {
    let icon = generate_app_icon();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 620.0])
            .with_min_inner_size([400.0, 560.0])
            .with_title(APP_NAME)
            .with_icon(std::sync::Arc::new(icon)),
        ..Default::default()
    };
    eframe::run_native(APP_NAME, options, Box::new(|cc| {
        setup_style(&cc.egui_ctx);
        Ok(Box::new(VpnApp::default()))
    })).ok();
}

fn cr(r: u8) -> egui::CornerRadius { egui::CornerRadius::same(r) }

fn setup_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(6.0, 5.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.text_edit_width = 400.0;
    style.spacing.interact_size.y = 32.0;
    style.visuals.window_corner_radius = cr(12);
    for w in [&mut style.visuals.widgets.noninteractive, &mut style.visuals.widgets.inactive, &mut style.visuals.widgets.hovered, &mut style.visuals.widgets.active] {
        w.corner_radius = cr(8);
    }
    let input_bg = egui::Color32::from_rgb(17, 24, 39);
    style.visuals.widgets.inactive.bg_fill = input_bg;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 65, 81));
    style.visuals.widgets.hovered.bg_fill = input_bg;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.5, egui::Color32::from_rgb(56, 189, 248));
    style.visuals.widgets.active.bg_fill = input_bg;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.5, egui::Color32::from_rgb(56, 189, 248));
    style.visuals.extreme_bg_color = input_bg;
    style.visuals.panel_fill = egui::Color32::from_rgb(15, 17, 23);
    style.visuals.window_fill = egui::Color32::from_rgb(15, 17, 23);
    style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(24, 25, 33);
    ctx.set_style(style);
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::default()
        .fill(egui::Color32::from_rgb(24, 25, 33))
        .corner_radius(cr(10))
        .inner_margin(12.0)
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)))
        .show(ui, add);
}

fn lbl(t: &str) -> egui::RichText {
    egui::RichText::new(t).size(11.0).color(egui::Color32::from_rgb(148, 155, 168))
}

impl eframe::App for VpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let state = self.state.lock().unwrap().clone();
        let status = self.status.lock().unwrap().clone();

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
            match state {
                ConnectionState::Connected => {
                    draw_header_connected(ui, self);
                    ui.add_space(6.0);
                    draw_connected(ui, &status);
                }
                ConnectionState::Connecting => {
                    draw_header(ui);
                    ui.vertical_centered(|ui| {
                        ui.add_space(30.0);
                        ui.spinner();
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new("Connecting...").size(14.0).color(egui::Color32::from_rgb(250, 204, 21)));
                    });
                    ctx.request_repaint_after(std::time::Duration::from_millis(200));
                }
                ConnectionState::Error(ref msg) => {
                    draw_header(ui);
                    draw_server_view(ui, self);
                    ui.add_space(4.0);
                    egui::Frame::default()
                        .fill(egui::Color32::from_rgba_premultiplied(220, 38, 38, 30))
                        .corner_radius(cr(8)).inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(msg).size(11.0).color(egui::Color32::from_rgb(248, 113, 113)));
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

        if matches!(state, ConnectionState::Connected) {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
    }
}

fn draw_header(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(8.0);
        draw_logo(ui);
        ui.add_space(4.0);
        ui.label(egui::RichText::new("NexGuard").size(20.0).strong().color(egui::Color32::WHITE));
        ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).size(10.0).color(egui::Color32::from_rgb(100, 116, 139)));
        ui.add_space(8.0);
    });
}

fn draw_header_connected(ui: &mut egui::Ui, app: &mut VpnApp) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        draw_logo(ui);
        ui.add_space(4.0);
        ui.vertical(|ui| {
        ui.horizontal(|ui| {
                ui.label(egui::RichText::new("NexGuard").size(16.0).strong().color(egui::Color32::WHITE));
                ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).size(10.0).color(egui::Color32::from_rgb(100, 116, 139)));
            });
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("●").size(11.0).color(egui::Color32::from_rgb(34, 197, 94)));
                ui.label(egui::RichText::new("Connected").size(11.0).strong().color(egui::Color32::from_rgb(34, 197, 94)));
            });
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            if ui.add(egui::Button::new(egui::RichText::new("Disconnect").size(12.0).color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(220, 38, 38))).clicked() {
                app.disconnect();
            }
        });
    });
    ui.add_space(2.0);
    ui.separator();
}

fn draw_server_view(ui: &mut egui::Ui, app: &mut VpnApp) {
    match app.view {
        View::ServerList => draw_server_list(ui, app),
        View::AddServer => draw_add_server(ui, app),
    }
}

fn draw_server_list(ui: &mut egui::Ui, app: &mut VpnApp) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Servers").size(13.0).strong().color(egui::Color32::WHITE));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(egui::Button::new(egui::RichText::new("+ Add Server").size(12.0)).min_size(egui::vec2(90.0, 28.0))).clicked() {
                app.view = View::AddServer;
            }
        });
    });
    ui.add_space(4.0);

    if app.profiles.is_empty() {
        draw_add_server(ui, app);
        return;
    } else {
        for (i, profile) in app.profiles.iter().enumerate() {
            let is_selected = app.selected == Some(i);
            let fill = if is_selected { egui::Color32::from_rgb(30, 35, 48) } else { egui::Color32::from_rgb(24, 25, 33) };
            let stroke_color = if is_selected { egui::Color32::from_rgb(56, 189, 248) } else { egui::Color32::from_rgb(48, 54, 61) };

            egui::Frame::default()
                .fill(fill)
                .corner_radius(cr(8))
                .inner_margin(10.0)
                .stroke(egui::Stroke::new(if is_selected { 1.5 } else { 1.0 }, stroke_color))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(&profile.name).size(13.0).strong().color(egui::Color32::WHITE));
                            ui.label(egui::RichText::new(&profile.server).size(11.0).color(egui::Color32::from_rgb(120, 130, 145)));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if is_selected && ui.small_button("✕").clicked() {
                                ui.ctx().data_mut(|d| d.insert_temp(egui::Id::new("del_idx"), i));
                            }
                            if !is_selected && ui.small_button("Select").clicked() {
                                ui.ctx().data_mut(|d| d.insert_temp(egui::Id::new("sel_idx"), i));
                            }
                        });
                    });
                });
            ui.add_space(2.0);
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

    ui.add_space(8.0);
    ui.vertical_centered(|ui| {
        let can_connect = app.selected.is_some() && !app.profiles.is_empty();
        let btn = egui::Button::new(egui::RichText::new("Connect").size(14.0).color(egui::Color32::WHITE))
            .fill(if can_connect { egui::Color32::from_rgb(56, 189, 248) } else { egui::Color32::from_rgb(55, 65, 81) })
            .min_size(egui::vec2(180.0, 36.0));
        if ui.add_enabled(can_connect, btn).clicked() {
            app.connect_selected();
        }
    });
}

fn draw_add_server(ui: &mut egui::Ui, app: &mut VpnApp) {
    ui.horizontal(|ui| {
        if ui.small_button("← Back").clicked() {
            app.view = View::ServerList;
        }
        ui.label(egui::RichText::new("Add Server").size(13.0).strong().color(egui::Color32::WHITE));
    });
    ui.add_space(4.0);

    card(ui, |ui| {
        ui.label(lbl("Name"));
        ui.add(egui::TextEdit::singleline(&mut app.new_name).hint_text("My VPN Server").desired_width(f32::INFINITY).margin(egui::vec2(8.0, 8.0)));

        ui.add_space(6.0);
        ui.label(lbl("Server"));
        ui.add(egui::TextEdit::singleline(&mut app.new_server).hint_text("192.168.1.100 or vpn.example.com").desired_width(f32::INFINITY).margin(egui::vec2(8.0, 8.0)));

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(lbl("Token"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(if app.show_token { "Hide" } else { "Show" }).clicked() {
                    app.show_token = !app.show_token;
                }
            });
        });
        ui.add(egui::TextEdit::singleline(&mut app.new_token).password(!app.show_token).hint_text("VPN access token").desired_width(f32::INFINITY).margin(egui::vec2(8.0, 8.0)));

        ui.add_space(6.0);
        ui.checkbox(&mut app.new_internet, "Route all traffic through VPN");
    });

    ui.add_space(8.0);
    ui.vertical_centered(|ui| {
        let ok = !app.new_server.is_empty();
        let btn = egui::Button::new(egui::RichText::new("Save Server").size(14.0).color(egui::Color32::WHITE))
            .fill(if ok { egui::Color32::from_rgb(56, 189, 248) } else { egui::Color32::from_rgb(55, 65, 81) })
            .min_size(egui::vec2(180.0, 36.0));
        if ui.add_enabled(ok, btn).clicked() {
            app.save_new_server();
        }
    });
}

fn draw_connected(ui: &mut egui::Ui, status: &Option<VpnStatus>) {
    let Some(ref st) = status else { return };
    let ip_only = st.address.split('/').next().unwrap_or(&st.address);
    let geo = st.geo.lock().unwrap().clone();

    card(ui, |ui| {
        ui.vertical_centered(|ui| {
            if let Some(ref g) = geo {
                ui.label(lbl("Public IP"));
                ui.label(egui::RichText::new(&g.ip).size(24.0).strong().color(egui::Color32::from_rgb(56, 189, 248)));
                let loc = if g.city.is_empty() { g.country.clone() } else { format!("{}, {}", g.city, g.country) };
                ui.label(egui::RichText::new(&loc).size(12.0).color(egui::Color32::from_rgb(250, 204, 21)));
                if !g.isp.is_empty() {
                    ui.label(egui::RichText::new(&g.isp).size(10.0).color(egui::Color32::from_rgb(148, 155, 168)));
                }
            } else {
                ui.label(lbl("VPN IP"));
                ui.label(egui::RichText::new(ip_only).size(24.0).strong().color(egui::Color32::from_rgb(56, 189, 248)));
                ui.label(egui::RichText::new("Detecting location...").size(10.0).color(egui::Color32::from_rgb(148, 155, 168)));
            }
        });
    });

    ui.add_space(4.0);
    let uptime = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs().saturating_sub(st.connected_at);
    ui.columns(4, |c| {
        mini_stat(&mut c[0], "TX", &fmt_bytes(st.tx.load(Ordering::Relaxed)), egui::Color32::from_rgb(56, 189, 248));
        mini_stat(&mut c[1], "RX", &fmt_bytes(st.rx.load(Ordering::Relaxed)), egui::Color32::from_rgb(139, 92, 246));
        mini_stat(&mut c[2], "Up", &fmt_uptime(uptime), egui::Color32::from_rgb(34, 197, 94));
        mini_stat(&mut c[3], "Mode", if st.internet_mode { "Full" } else { "VPN" }, egui::Color32::from_rgb(59, 130, 246));
    });

    ui.add_space(4.0);
    card(ui, |ui| {
        row(ui, "Internal IP", ip_only);
        ui.separator();
        if let Some(ref g) = geo { if !g.region.is_empty() { row(ui, "Region", &g.region); ui.separator(); } }
        row(ui, "Server", &st.server);
        ui.separator();
        row(ui, "Endpoint", &st.endpoint);
        ui.separator();
        row(ui, "Interface", &st.tun_name);
    });
}

fn draw_update_banner(ui: &mut egui::Ui, app: &mut VpnApp) {
    if let Some(ref result) = app.update_result.lock().unwrap().clone() {
        ui.add_space(6.0);
        let (msg, bg, text_color) = match result {
            Ok(()) => ("Updated! Restart the app to use the new version.", egui::Color32::from_rgb(20, 55, 35), egui::Color32::WHITE),
            Err(e) => (e.as_str(), egui::Color32::from_rgb(65, 25, 25), egui::Color32::from_rgb(255, 180, 180)),
        };
        egui::Frame::default().fill(bg).corner_radius(cr(10)).inner_margin(12.0)
            .show(ui, |ui| { ui.label(egui::RichText::new(msg).size(13.0).strong().color(text_color)); });
        return;
    }
    if app.updating.load(Ordering::Relaxed) {
        ui.add_space(4.0);
        ui.horizontal(|ui| { ui.spinner(); ui.label(egui::RichText::new("Updating...").size(12.0).color(egui::Color32::from_rgb(250, 204, 21))); });
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        return;
    }
    let info = app.update_info.lock().unwrap().clone();
    if let Some(ref info) = info {
        if !info.has_update { return; }
        ui.add_space(6.0);
        egui::Frame::default()
            .fill(egui::Color32::from_rgb(30, 58, 75))
            .corner_radius(cr(10))
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("New version v{} available", info.version))
                        .size(13.0).strong().color(egui::Color32::WHITE));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let url = info.download_url.clone();
                        let btn = egui::Button::new(
                            egui::RichText::new("Update Now").size(12.0).color(egui::Color32::WHITE),
                        ).fill(egui::Color32::from_rgb(56, 189, 248)).min_size(egui::vec2(90.0, 28.0));
                        if ui.add(btn).clicked() { app.start_update(url); }
                    });
                });
            });
    }
}

fn mini_stat(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32) {
    egui::Frame::default().fill(egui::Color32::from_rgb(24, 25, 33)).corner_radius(cr(8)).inner_margin(8.0)
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).size(9.0).color(egui::Color32::from_rgb(148, 155, 168)));
            ui.label(egui::RichText::new(value).size(13.0).strong().color(color));
        });
}

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(lbl(label));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(value).size(11.0).color(egui::Color32::from_rgb(200, 200, 210)));
        });
    });
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

fn draw_logo(ui: &mut egui::Ui) {
    let size = 40.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let p = ui.painter();
    let c = rect.center();
    let bg = egui::Rect::from_center_size(c, egui::vec2(size, size));
    p.rect_filled(bg, cr(10), egui::Color32::from_rgb(15, 23, 42));
    p.rect_stroke(bg, cr(10), egui::Stroke::new(1.5, egui::Color32::from_rgb(56, 189, 248)), egui::StrokeKind::Outside);
    let s = size * 0.32;
    let shield = vec![
        egui::pos2(c.x, c.y - s * 0.9), egui::pos2(c.x + s * 0.75, c.y - s * 0.25),
        egui::pos2(c.x + s * 0.55, c.y + s * 0.45), egui::pos2(c.x, c.y + s * 1.0),
        egui::pos2(c.x - s * 0.55, c.y + s * 0.45), egui::pos2(c.x - s * 0.75, c.y - s * 0.25),
    ];
    p.add(egui::Shape::convex_polygon(shield, egui::Color32::from_rgb(56, 189, 248), egui::Stroke::NONE));
    let is = s * 0.55;
    let lcy = c.y + s * 0.15;
    let body = egui::Rect::from_center_size(egui::pos2(c.x, lcy + is * 0.15), egui::vec2(is * 0.7, is * 0.55));
    p.rect_filled(body, cr(2), egui::Color32::from_rgb(15, 23, 42));
    let ar = is * 0.25;
    let acy = lcy - is * 0.12;
    for i in 0..12 {
        let a1 = std::f32::consts::PI + (std::f32::consts::PI * i as f32 / 12.0);
        let a2 = std::f32::consts::PI + (std::f32::consts::PI * (i + 1) as f32 / 12.0);
        p.line_segment(
            [egui::pos2(c.x + ar * a1.cos(), acy + ar * a1.sin()), egui::pos2(c.x + ar * a2.cos(), acy + ar * a2.sin())],
            egui::Stroke::new(1.5, egui::Color32::from_rgb(15, 23, 42)),
        );
    }
}

fn generate_app_icon() -> egui::IconData {
    const SZ: usize = 128;
    let mut rgba = vec![0u8; SZ * SZ * 4];
    let cx = SZ as f32 / 2.0; let cy = SZ as f32 / 2.0; let r = SZ as f32 * 0.45;
    for y in 0..SZ { for x in 0..SZ {
        let dx = (x as f32 - cx).abs(); let dy = (y as f32 - cy).abs(); let cr = 20.0;
        let inside = if dx > cx - cr && dy > cy - cr { let a = dx - (cx - cr); let b = dy - (cy - cr); a*a + b*b <= cr*cr } else { dx <= cx && dy <= cy };
        if inside { let i = (y * SZ + x) * 4; rgba[i] = 15; rgba[i+1] = 23; rgba[i+2] = 42; rgba[i+3] = 255; }
    }}
    let pts = [(cx, cy - r*0.72), (cx + r*0.6, cy - r*0.2), (cx + r*0.44, cy + r*0.36), (cx, cy + r*0.8), (cx - r*0.44, cy + r*0.36), (cx - r*0.6, cy - r*0.2)];
    for y in 0..SZ { for x in 0..SZ { if point_in_polygon(x as f32, y as f32, &pts) { let i = (y*SZ+x)*4; rgba[i]=56; rgba[i+1]=189; rgba[i+2]=248; rgba[i+3]=255; } }}
    egui::IconData { rgba, width: SZ as u32, height: SZ as u32 }
}

fn point_in_polygon(px: f32, py: f32, pts: &[(f32, f32)]) -> bool {
    let mut inside = false; let n = pts.len(); let mut j = n - 1;
    for i in 0..n { let (xi,yi) = pts[i]; let (xj,yj) = pts[j];
        if ((yi > py) != (yj > py)) && (px < (xj-xi)*(py-yi)/(yj-yi)+xi) { inside = !inside; } j = i; }
    inside
}
