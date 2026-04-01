use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::vpn::{VpnConfig, VpnStatus};

#[derive(Clone, PartialEq)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

struct VpnApp {
    server: String,
    token: String,
    client_name: String,
    internet_mode: bool,
    state: Arc<Mutex<ConnectionState>>,
    status: Arc<Mutex<Option<VpnStatus>>>,
    shutdown: Arc<AtomicBool>,
    show_token: bool,
}

impl Default for VpnApp {
    fn default() -> Self {
        Self {
            server: std::env::var("VPN_SERVER").unwrap_or_default(),
            token: std::env::var("VPN_TOKEN").unwrap_or_default(),
            client_name: String::new(),
            internet_mode: true,
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            status: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(AtomicBool::new(false)),
            show_token: false,
        }
    }
}

impl VpnApp {
    fn connect(&mut self) {
        let config = VpnConfig {
            server: self.server.clone(),
            token: self.token.clone(),
            name: self.client_name.clone(),
            internet: self.internet_mode,
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
                Err(e) => {
                    *state.lock().unwrap() = ConnectionState::Error(e);
                }
            }
        });
    }

    fn disconnect(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(500));
        *self.state.lock().unwrap() = ConnectionState::Disconnected;
        *self.status.lock().unwrap() = None;
    }
}

const APP_NAME: &str = "NexGuard VPN";

pub fn run_gui() {
    let icon = generate_app_icon();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 520.0])
            .with_min_inner_size([380.0, 460.0])
            .with_title(APP_NAME)
            .with_icon(std::sync::Arc::new(icon)),
        ..Default::default()
    };

    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            Ok(Box::new(VpnApp::default()))
        }),
    )
    .ok();
}

fn generate_app_icon() -> egui::IconData {
    const SZ: usize = 128;
    let mut rgba = vec![0u8; SZ * SZ * 4];
    let cx = SZ as f32 / 2.0;
    let cy = SZ as f32 / 2.0;
    let r = SZ as f32 * 0.45;

    for y in 0..SZ {
        for x in 0..SZ {
            let dx = (x as f32 - cx).abs();
            let dy = (y as f32 - cy).abs();
            let cr = 20.0;
            let inside = if dx > cx - cr && dy > cy - cr {
                let a = dx - (cx - cr);
                let b = dy - (cy - cr);
                a * a + b * b <= cr * cr
            } else {
                dx <= cx && dy <= cy
            };
            if inside {
                let i = (y * SZ + x) * 4;
                rgba[i] = 15; rgba[i + 1] = 23; rgba[i + 2] = 42; rgba[i + 3] = 255;
            }
        }
    }

    let pts: [(f32, f32); 6] = [
        (cx, cy - r * 0.72), (cx + r * 0.6, cy - r * 0.2),
        (cx + r * 0.44, cy + r * 0.36), (cx, cy + r * 0.8),
        (cx - r * 0.44, cy + r * 0.36), (cx - r * 0.6, cy - r * 0.2),
    ];
    for y in 0..SZ {
        for x in 0..SZ {
            if point_in_polygon(x as f32, y as f32, &pts) {
                let i = (y * SZ + x) * 4;
                rgba[i] = 6; rgba[i + 1] = 182; rgba[i + 2] = 212; rgba[i + 3] = 255;
            }
        }
    }

    let lock_w = r * 0.32;
    let lock_h = r * 0.26;
    let lock_cy = cy + r * 0.16;
    for y in 0..SZ {
        for x in 0..SZ {
            let fx = x as f32;
            let fy = y as f32;
            if (fx - cx).abs() <= lock_w / 2.0 && fy >= lock_cy && fy <= lock_cy + lock_h {
                let i = (y * SZ + x) * 4;
                rgba[i] = 15; rgba[i + 1] = 23; rgba[i + 2] = 42; rgba[i + 3] = 255;
            }
        }
    }

    let arc_r = r * 0.15 * 0.55;
    let arc_cy2 = lock_cy - r * 0.02 * 0.55;
    for y in 0..SZ {
        for x in 0..SZ {
            let fy = y as f32;
            if fy > arc_cy2 { continue; }
            let dist = ((x as f32 - cx).powi(2) + (fy - arc_cy2).powi(2)).sqrt();
            if (dist - arc_r).abs() <= 3.5 {
                let i = (y * SZ + x) * 4;
                rgba[i] = 15; rgba[i + 1] = 23; rgba[i + 2] = 42; rgba[i + 3] = 255;
            }
        }
    }

    egui::IconData { rgba, width: SZ as u32, height: SZ as u32 }
}

fn point_in_polygon(px: f32, py: f32, pts: &[(f32, f32)]) -> bool {
    let mut inside = false;
    let n = pts.len();
    let mut j = n - 1;
    for i in 0..n {
        let (xi, yi) = pts[i];
        let (xj, yj) = pts[j];
        if ((yi > py) != (yj > py)) && (px < (xj - xi) * (py - yi) / (yj - yi) + xi) {
            inside = !inside;
        }
        j = i;
    }
    inside
}

fn cr(r: u8) -> egui::CornerRadius { egui::CornerRadius::same(r) }

fn setup_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(6.0, 5.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.text_edit_width = 400.0;
    style.spacing.interact_size.y = 32.0;
    style.visuals.window_corner_radius = cr(12);
    for w in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
    ] {
        w.corner_radius = cr(8);
    }

    let input_bg = egui::Color32::from_rgb(17, 24, 39);
    style.visuals.widgets.inactive.bg_fill = input_bg;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 65, 81));
    style.visuals.widgets.hovered.bg_fill = input_bg;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.5, egui::Color32::from_rgb(6, 182, 212));
    style.visuals.widgets.active.bg_fill = input_bg;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.5, egui::Color32::from_rgb(6, 182, 212));
    style.visuals.extreme_bg_color = input_bg;
    style.visuals.panel_fill = egui::Color32::from_rgb(14, 17, 23);
    style.visuals.window_fill = egui::Color32::from_rgb(14, 17, 23);
    style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(22, 27, 34);
    ctx.set_style(style);
}

fn draw_logo(ui: &mut egui::Ui) {
    let size = 40.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let p = ui.painter();
    let c = rect.center();
    let bg = egui::Rect::from_center_size(c, egui::vec2(size, size));
    p.rect_filled(bg, cr(10), egui::Color32::from_rgb(15, 23, 42));
    p.rect_stroke(bg, cr(10), egui::Stroke::new(1.5, egui::Color32::from_rgb(6, 182, 212)), egui::StrokeKind::Outside);
    let s = size * 0.32;
    let shield = vec![
        egui::pos2(c.x, c.y - s * 0.9), egui::pos2(c.x + s * 0.75, c.y - s * 0.25),
        egui::pos2(c.x + s * 0.55, c.y + s * 0.45), egui::pos2(c.x, c.y + s * 1.0),
        egui::pos2(c.x - s * 0.55, c.y + s * 0.45), egui::pos2(c.x - s * 0.75, c.y - s * 0.25),
    ];
    p.add(egui::Shape::convex_polygon(shield, egui::Color32::from_rgb(6, 182, 212), egui::Stroke::NONE));
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
            [egui::pos2(c.x + ar * a1.cos(), acy + ar * a1.sin()),
             egui::pos2(c.x + ar * a2.cos(), acy + ar * a2.sin())],
            egui::Stroke::new(1.5, egui::Color32::from_rgb(15, 23, 42)),
        );
    }
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::default()
        .fill(egui::Color32::from_rgb(22, 27, 34))
        .corner_radius(cr(10))
        .inner_margin(12.0)
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)))
        .show(ui, add);
}

fn lbl(t: &str) -> egui::RichText {
    egui::RichText::new(t).size(11.0).color(egui::Color32::from_rgb(139, 148, 158))
}

impl eframe::App for VpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let state = self.state.lock().unwrap().clone();
        let status = self.status.lock().unwrap().clone();

        egui::CentralPanel::default().show(ctx, |ui| {
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
                        ui.label(egui::RichText::new("Connecting...").size(14.0)
                            .color(egui::Color32::from_rgb(250, 204, 21)));
                    });
                    ctx.request_repaint_after(std::time::Duration::from_millis(200));
                }
                ConnectionState::Error(ref msg) => {
                    draw_header(ui);
                    draw_form(ui, self);
                    ui.add_space(4.0);
                    egui::Frame::default()
                        .fill(egui::Color32::from_rgba_premultiplied(220, 38, 38, 30))
                        .corner_radius(cr(8))
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(msg).size(11.0)
                                .color(egui::Color32::from_rgb(248, 113, 113)));
                        });
                }
                ConnectionState::Disconnected => {
                    draw_header(ui);
                    draw_form(ui, self);
                }
            }
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
        ui.label(egui::RichText::new("Secure Tunnel").size(10.0)
            .color(egui::Color32::from_rgb(100, 116, 139)));
        ui.add_space(10.0);
    });
}

fn draw_header_connected(ui: &mut egui::Ui, app: &mut VpnApp) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        draw_logo(ui);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.label(egui::RichText::new("NexGuard").size(16.0).strong().color(egui::Color32::WHITE));
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("●").size(11.0)
                    .color(egui::Color32::from_rgb(34, 197, 94)));
                ui.label(egui::RichText::new("Connected").size(11.0).strong()
                    .color(egui::Color32::from_rgb(34, 197, 94)));
            });
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            let btn = egui::Button::new(
                egui::RichText::new("Disconnect").size(12.0).color(egui::Color32::WHITE),
            )
            .fill(egui::Color32::from_rgb(220, 38, 38));
            if ui.add(btn).clicked() {
                app.disconnect();
            }
        });
    });
    ui.add_space(2.0);
    ui.separator();
}

fn draw_form(ui: &mut egui::Ui, app: &mut VpnApp) {
    card(ui, |ui| {
        ui.label(lbl("Server"));
        ui.add(egui::TextEdit::singleline(&mut app.server)
            .hint_text("192.168.1.100 or vpn.example.com")
            .desired_width(f32::INFINITY).margin(egui::vec2(8.0, 8.0)));

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(lbl("Token"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(if app.show_token { "Hide" } else { "Show" }).clicked() {
                    app.show_token = !app.show_token;
                }
            });
        });
        ui.add(egui::TextEdit::singleline(&mut app.token)
            .password(!app.show_token).hint_text("VPN access token")
            .desired_width(f32::INFINITY).margin(egui::vec2(8.0, 8.0)));

        ui.add_space(6.0);
        ui.label(lbl("Client Name (optional)"));
        ui.add(egui::TextEdit::singleline(&mut app.client_name)
            .hint_text("auto-generated if empty")
            .desired_width(f32::INFINITY).margin(egui::vec2(8.0, 8.0)));

        ui.add_space(6.0);
        ui.checkbox(&mut app.internet_mode, "Route all traffic through VPN");
    });

    ui.add_space(8.0);
    ui.vertical_centered(|ui| {
        let ok = !app.server.is_empty();
        let btn = egui::Button::new(
            egui::RichText::new("Connect").size(14.0).color(egui::Color32::WHITE),
        )
        .fill(if ok { egui::Color32::from_rgb(6, 182, 212) } else { egui::Color32::from_rgb(55, 65, 81) })
        .min_size(egui::vec2(180.0, 36.0));
        if ui.add_enabled(ok, btn).clicked() { app.connect(); }
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
                ui.label(egui::RichText::new(&g.ip).size(24.0).strong()
                    .color(egui::Color32::from_rgb(6, 182, 212)));
                let loc = if g.city.is_empty() { g.country.clone() }
                    else { format!("{}, {}", g.city, g.country) };
                ui.label(egui::RichText::new(&loc).size(12.0)
                    .color(egui::Color32::from_rgb(250, 204, 21)));
                if !g.isp.is_empty() {
                    ui.label(egui::RichText::new(&g.isp).size(10.0)
                        .color(egui::Color32::from_rgb(139, 148, 158)));
                }
            } else {
                ui.label(lbl("VPN IP"));
                ui.label(egui::RichText::new(ip_only).size(24.0).strong()
                    .color(egui::Color32::from_rgb(6, 182, 212)));
                ui.label(egui::RichText::new("Detecting location...").size(10.0)
                    .color(egui::Color32::from_rgb(139, 148, 158)));
            }
            if let Some(ref v6) = st.address_v6 {
                let v6ip = v6.split('/').next().unwrap_or(v6);
                ui.label(egui::RichText::new(v6ip).size(11.0)
                    .color(egui::Color32::from_rgb(139, 92, 246)));
            }
        });
    });

    ui.add_space(4.0);

    let uptime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
        .saturating_sub(st.connected_at);

    ui.columns(4, |c| {
        mini_stat(&mut c[0], "TX", &fmt_bytes(st.tx.load(Ordering::Relaxed)), egui::Color32::from_rgb(6, 182, 212));
        mini_stat(&mut c[1], "RX", &fmt_bytes(st.rx.load(Ordering::Relaxed)), egui::Color32::from_rgb(139, 92, 246));
        mini_stat(&mut c[2], "Up", &fmt_uptime(uptime), egui::Color32::from_rgb(34, 197, 94));
        mini_stat(&mut c[3], "Mode", if st.internet_mode { "Full" } else { "VPN" }, egui::Color32::from_rgb(59, 130, 246));
    });

    ui.add_space(4.0);

    card(ui, |ui| {
        row(ui, "Internal IP", ip_only);
        ui.separator();
        if let Some(ref g) = geo {
            if !g.region.is_empty() {
                row(ui, "Region", &g.region);
                ui.separator();
            }
        }
        row(ui, "Server", &st.server);
        ui.separator();
        row(ui, "Endpoint", &st.endpoint);
        ui.separator();
        row(ui, "Interface", &st.tun_name);
    });
}

fn mini_stat(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32) {
    egui::Frame::default()
        .fill(egui::Color32::from_rgb(22, 27, 34))
        .corner_radius(cr(8))
        .inner_margin(8.0)
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).size(9.0)
                .color(egui::Color32::from_rgb(139, 148, 158)));
            ui.label(egui::RichText::new(value).size(13.0).strong().color(color));
        });
}

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(lbl(label));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(value).size(11.0)
                .color(egui::Color32::from_rgb(200, 200, 210)));
        });
    });
}

fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    if b < KB { format!("{} B", b) }
    else if b < MB { format!("{:.1} KB", b as f64 / KB as f64) }
    else if b < GB { format!("{:.1} MB", b as f64 / MB as f64) }
    else { format!("{:.1} GB", b as f64 / GB as f64) }
}

fn fmt_uptime(s: u64) -> String {
    if s < 60 { format!("{}s", s) }
    else if s < 3600 { format!("{}m{}s", s / 60, s % 60) }
    else { format!("{}h{}m", s / 3600, (s % 3600) / 60) }
}
