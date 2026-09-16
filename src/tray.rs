use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder, TrayIcon};

use crate::protocol::SessionView;
use crate::meshnet::PeerPath;

const ICON_SIZE: u32 = 22;
const TITLE_IDLE: &str = "NexGuard — Not connected";
const TITLE_CONNECTED: &str = "NexGuard — Connected";
const ACTION_CONNECT: &str = "Connect";
const ACTION_DISCONNECT: &str = "Disconnect";
const MENU_SHOW: &str = "Show Window";
const MENU_QUIT: &str = "Quit NexGuard";

pub struct NexTray {
    _tray: TrayIcon,
    item_status: MenuItem,
    item_toggle: MenuItem,
    item_ip: MenuItem,
    item_tx_rx: MenuItem,
    item_devices: MenuItem,
    toggle_id: tray_icon::menu::MenuId,
    show_id: tray_icon::menu::MenuId,
    quit_id: tray_icon::menu::MenuId,
    icon_on: Icon,
    icon_off: Icon,
    was_connected: bool,
    mesh_status: Arc<Mutex<Option<SessionView>>>,
    connect_trigger: Arc<AtomicBool>,
    pub quit_requested: bool,
    pub disconnect_requested: bool,
    pub show_requested: bool,
}

pub struct TrayChannels {
    pub mesh_status: Arc<Mutex<Option<SessionView>>>,
    pub connect_trigger: Arc<AtomicBool>,
}

struct TrayView {
    title: &'static str,
    toggle: &'static str,
    ip: String,
    traffic: String,
    devices: String,
    connected: bool,
}

impl NexTray {
    pub fn new(channels: TrayChannels) -> Option<Self> {
        let menu = Menu::new();

        let item_status = MenuItem::new(TITLE_IDLE, false, None);
        let item_toggle = MenuItem::new(ACTION_CONNECT, true, None);
        let item_ip = MenuItem::new("", false, None);
        let item_tx_rx = MenuItem::new("", false, None);
        let item_devices = MenuItem::new("", false, None);
        let item_show = MenuItem::new(MENU_SHOW, true, None);
        let item_quit = MenuItem::new(MENU_QUIT, true, None);

        let _ = menu.append(&item_status);
        let _ = menu.append(&item_toggle);
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&item_ip);
        let _ = menu.append(&item_tx_rx);
        let _ = menu.append(&item_devices);
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&item_show);
        let _ = menu.append(&item_quit);

        let icon_off = make_icon(false);
        let icon_on = make_icon(true);

        let builder = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("NexGuard")
            .with_icon(icon_off.clone());
        #[cfg(target_os = "macos")]
        let builder = builder.with_icon_as_template(true);
        let tray = builder.build().ok()?;

        let toggle_id = item_toggle.id().clone();
        let show_id = item_show.id().clone();
        let quit_id = item_quit.id().clone();

        Some(Self {
            _tray: tray,
            item_status,
            item_toggle,
            item_ip,
            item_tx_rx,
            item_devices,
            toggle_id,
            show_id,
            quit_id,
            icon_on,
            icon_off,
            was_connected: false,
            mesh_status: channels.mesh_status,
            connect_trigger: channels.connect_trigger,
            quit_requested: false,
            disconnect_requested: false,
            show_requested: false,
        })
    }

    pub fn tick(&mut self) {
        let view = self.compose();

        if let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.toggle_id {
                if view.connected {
                    self.disconnect_requested = true;
                } else {
                    self.connect_trigger.store(true, Ordering::Relaxed);
                }
            } else if event.id == self.show_id {
                self.show_requested = true;
            } else if event.id == self.quit_id {
                self.quit_requested = true;
            }
        }

        if view.connected || view.connected != self.was_connected {
            self.item_status.set_text(view.title);
            self.item_toggle.set_text(view.toggle);
            self.item_ip.set_text(&view.ip);
            self.item_tx_rx.set_text(&view.traffic);
            self.item_devices.set_text(&view.devices);
            let icon = if view.connected { &self.icon_on } else { &self.icon_off };
            let _ = self._tray.set_icon(Some(icon.clone()));
            self.was_connected = view.connected;
        }
    }

    fn compose(&self) -> TrayView {
        let mesh = self.mesh_status.lock().ok().and_then(|s| s.clone());
        let Some(status) = mesh else {
            return TrayView {
                title: TITLE_IDLE,
                toggle: ACTION_CONNECT,
                ip: String::new(),
                traffic: String::new(),
                devices: String::new(),
                connected: false,
            };
        };
        let direct = status.peers.iter().filter(|p| p.path == PeerPath::Direct).count();
        let online = status.peers.iter().filter(|p| p.path != PeerPath::Offline).count();
        TrayView {
            title: TITLE_CONNECTED,
            toggle: ACTION_DISCONNECT,
            ip: format!("IP: {}", status.address),
            traffic: traffic_text(status.tx, status.rx),
            devices: format!("Devices: {} online, {} direct", online, direct),
            connected: true,
        }
    }
}

fn traffic_text(tx: u64, rx: u64) -> String {
    format!("TX: {}  RX: {}", fmt_bytes(tx), fmt_bytes(rx))
}

fn make_icon(connected: bool) -> Icon {
    let size = ICON_SIZE as usize;
    let png = include_bytes!("../assets/logo-glyph-64.png");
    let img = image::load_from_memory(png).unwrap().to_rgba8();
    let resized = image::imageops::resize(&img, size as u32, size as u32, image::imageops::FilterType::Lanczos3);
    let mut rgba = resized.into_raw();

    #[cfg(target_os = "macos")]
    for i in (0..rgba.len()).step_by(4) {
        let a = rgba[i + 3] as u16;
        rgba[i] = 255;
        rgba[i + 1] = 255;
        rgba[i + 2] = 255;
        rgba[i + 3] = if connected { a as u8 } else { (a * 2 / 5) as u8 };
    }

    #[cfg(not(target_os = "macos"))]
    if !connected {
        for i in (0..rgba.len()).step_by(4) {
            if rgba[i + 3] > 0 {
                let lum = (rgba[i] as u16 + rgba[i + 1] as u16 + rgba[i + 2] as u16) / 3;
                rgba[i] = lum as u8;
                rgba[i + 1] = lum as u8;
                rgba[i + 2] = lum as u8;
                rgba[i + 3] = rgba[i + 3] / 2;
            }
        }
    }

    Icon::from_rgba(rgba, size as u32, size as u32).unwrap_or_else(|_| {
        Icon::from_rgba(vec![0; 4], 1, 1).unwrap()
    })
}

fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    if b < KB { format!("{} B", b) }
    else if b < MB { format!("{:.1} KB", b as f64 / KB as f64) }
    else { format!("{:.1} MB", b as f64 / MB as f64) }
}
