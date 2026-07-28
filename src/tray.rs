use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIconBuilder, TrayIcon};

use crate::profiles::ServerProfile;
use crate::vpn::{ConnectionState, VpnStatus};

const ICON_SIZE: u32 = 22;

pub struct NexTray {
    _tray: TrayIcon,
    item_status: MenuItem,
    item_toggle: MenuItem,
    item_ip: MenuItem,
    item_tx_rx: MenuItem,
    server_items: Vec<(MenuItem, usize)>,
    servers_sub: Submenu,
    toggle_id: tray_icon::menu::MenuId,
    show_id: tray_icon::menu::MenuId,
    quit_id: tray_icon::menu::MenuId,
    icon_on: Icon,
    icon_off: Icon,
    was_connected: bool,
    status: Arc<Mutex<Option<VpnStatus>>>,
    state: Arc<Mutex<ConnectionState>>,
    shutdown: Arc<AtomicBool>,
    connect_trigger: Arc<AtomicBool>,
    selected_server: Arc<AtomicUsize>,
    pub quit_requested: bool,
    pub reconnect_after_disconnect: bool,
    pub show_requested: bool,
}

impl NexTray {
    pub fn new(
        status: Arc<Mutex<Option<VpnStatus>>>,
        state: Arc<Mutex<ConnectionState>>,
        shutdown: Arc<AtomicBool>,
        connect_trigger: Arc<AtomicBool>,
        selected_server: Arc<AtomicUsize>,
        profiles: &[ServerProfile],
    ) -> Option<Self> {
        let menu = Menu::new();

        let item_status = MenuItem::new("NexGuard — Disconnected", false, None);
        let item_toggle = MenuItem::new("Connect", true, None);
        let servers_sub = Submenu::new("Servers", true);
        let item_ip = MenuItem::new("", false, None);
        let item_tx_rx = MenuItem::new("", false, None);
        let item_show = MenuItem::new("Show Window", true, None);
        let item_quit = MenuItem::new("Quit NexGuard", true, None);

        let mut server_items = Vec::new();
        for (i, p) in profiles.iter().enumerate() {
            let label = if i == 0 {
                format!("● {}", p.name)
            } else {
                p.name.clone()
            };
            let item = MenuItem::new(&label, true, None);
            server_items.push((item.clone(), i));
            let _ = servers_sub.append(&item);
        }

        let _ = menu.append(&item_status);
        let _ = menu.append(&item_toggle);
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&servers_sub);
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&item_ip);
        let _ = menu.append(&item_tx_rx);
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&item_show);
        let _ = menu.append(&item_quit);

        let icon_off = make_icon(false);
        let icon_on = make_icon(true);

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("NexGuard VPN")
            .with_icon(icon_off.clone())
            .build()
            .ok()?;

        let toggle_id = item_toggle.id().clone();
        let show_id = item_show.id().clone();
        let quit_id = item_quit.id().clone();

        Some(Self {
            _tray: tray,
            item_status,
            item_toggle,
            item_ip,
            item_tx_rx,
            server_items,
            servers_sub,
            toggle_id,
            show_id,
            quit_id,
            icon_on,
            icon_off,
            was_connected: false,
            status,
            state,
            shutdown,
            connect_trigger,
            selected_server,
            quit_requested: false,
            reconnect_after_disconnect: false,
            show_requested: false,
        })
    }

    pub fn update_servers(&mut self, profiles: &[ServerProfile], selected: usize) {
        for (item, _) in &self.server_items {
            let _ = self.servers_sub.remove(item);
        }
        self.server_items.clear();
        for (i, p) in profiles.iter().enumerate() {
            let label = if i == selected {
                format!("● {}", p.name)
            } else {
                p.name.clone()
            };
            let item = MenuItem::new(&label, true, None);
            self.server_items.push((item.clone(), i));
            let _ = self.servers_sub.append(&item);
        }
    }

    fn session_active(&self) -> bool {
        !matches!(
            *self.state.lock().unwrap(),
            ConnectionState::Disconnected | ConnectionState::Error(_)
        )
    }

    pub fn tick(&mut self) {
        if let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.toggle_id {
                if self.session_active() {
                    self.shutdown.store(true, Ordering::Relaxed);
                } else {
                    self.connect_trigger.store(true, Ordering::Relaxed);
                }
            } else if event.id == self.show_id {
                self.show_requested = true;
            } else if event.id == self.quit_id {
                self.shutdown.store(true, Ordering::Relaxed);
                self.quit_requested = true;
            } else {
                for (item, idx) in &self.server_items {
                    if event.id == *item.id() {
                        self.selected_server.store(*idx, Ordering::Relaxed);
                        self.connect_trigger.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }

        let connected = matches!(
            *self.state.lock().unwrap(),
            ConnectionState::Connected | ConnectionState::Degraded
        );

        if connected != self.was_connected || connected {
            if connected {
                let guard = self.status.lock().unwrap();
                if let Some(ref st) = *guard {
                    let ip = st.address.split('/').next().unwrap_or(&st.address);
                    let tx = st.tx.load(Ordering::Relaxed);
                    let rx = st.rx.load(Ordering::Relaxed);
                    self.item_status.set_text("NexGuard — Connected");
                    self.item_toggle.set_text("Disconnect");
                    self.item_ip.set_text(format!("IP: {}", ip));
                    self.item_tx_rx.set_text(format!("TX: {}  RX: {}", fmt_bytes(tx), fmt_bytes(rx)));
                }
                let _ = self._tray.set_icon(Some(self.icon_on.clone()));
            } else {
                self.item_status.set_text("NexGuard — Disconnected");
                self.item_toggle.set_text("Connect");
                self.item_ip.set_text("");
                self.item_tx_rx.set_text("");
                let _ = self._tray.set_icon(Some(self.icon_off.clone()));
            }
            self.was_connected = connected;
        }
    }
}

fn make_icon(connected: bool) -> Icon {
    let size = ICON_SIZE as usize;
    let png = include_bytes!("../assets/logo-64.png");
    let img = image::load_from_memory(png).unwrap().to_rgba8();
    let resized = image::imageops::resize(&img, size as u32, size as u32, image::imageops::FilterType::Lanczos3);
    let mut rgba = resized.into_raw();

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
