use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder, TrayIcon};

use crate::vpn::VpnStatus;

const ICON_SIZE: u32 = 22;

pub struct NexTray {
    _tray: TrayIcon,
    item_status: MenuItem,
    item_toggle: MenuItem,
    item_ip: MenuItem,
    item_tx_rx: MenuItem,
    toggle_id: tray_icon::menu::MenuId,
    quit_id: tray_icon::menu::MenuId,
    icon_on: Icon,
    icon_off: Icon,
    was_connected: bool,
    status: Arc<Mutex<Option<VpnStatus>>>,
    shutdown: Arc<AtomicBool>,
    connect_trigger: Arc<AtomicBool>,
}

impl NexTray {
    pub fn new(
        status: Arc<Mutex<Option<VpnStatus>>>,
        shutdown: Arc<AtomicBool>,
        connect_trigger: Arc<AtomicBool>,
    ) -> Option<Self> {
        let menu = Menu::new();

        let item_status = MenuItem::new("NexGuard — Disconnected", false, None);
        let item_toggle = MenuItem::new("Connect", true, None);
        let item_ip = MenuItem::new("", false, None);
        let item_tx_rx = MenuItem::new("", false, None);
        let item_quit = MenuItem::new("Quit NexGuard", true, None);

        let _ = menu.append(&item_status);
        let _ = menu.append(&item_toggle);
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&item_ip);
        let _ = menu.append(&item_tx_rx);
        let _ = menu.append(&PredefinedMenuItem::separator());
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
        let quit_id = item_quit.id().clone();

        Some(Self {
            _tray: tray,
            item_status,
            item_toggle,
            item_ip,
            item_tx_rx,
            toggle_id,
            quit_id,
            icon_on,
            icon_off,
            was_connected: false,
            status,
            shutdown,
            connect_trigger,
        })
    }

    pub fn tick(&mut self) {
        if let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.toggle_id {
                let connected = self.status.lock().unwrap().is_some();
                if connected {
                    self.shutdown.store(true, Ordering::Relaxed);
                } else {
                    self.connect_trigger.store(true, Ordering::Relaxed);
                }
            } else if event.id == self.quit_id {
                self.shutdown.store(true, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(500));
                std::process::exit(0);
            }
        }

        let connected = self.status.lock().unwrap().is_some();

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
    let mut rgba = vec![0u8; size * size * 4];
    let cx = size as f32 / 2.0;
    let cy = size as f32 / 2.0;
    let r = size as f32 * 0.42;

    let (cr, cg, cb) = if connected { (34, 197, 94) } else { (148, 155, 168) };

    let pts = [
        (cx, cy - r * 0.9),
        (cx + r * 0.75, cy - r * 0.25),
        (cx + r * 0.55, cy + r * 0.45),
        (cx, cy + r),
        (cx - r * 0.55, cy + r * 0.45),
        (cx - r * 0.75, cy - r * 0.25),
    ];

    for y in 0..size {
        for x in 0..size {
            if point_in_polygon(x as f32, y as f32, &pts) {
                let i = (y * size + x) * 4;
                rgba[i] = cr;
                rgba[i + 1] = cg;
                rgba[i + 2] = cb;
                rgba[i + 3] = 255;
            }
        }
    }

    Icon::from_rgba(rgba, size as u32, size as u32).unwrap_or_else(|_| {
        Icon::from_rgba(vec![0; 4], 1, 1).unwrap()
    })
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

fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    if b < KB { format!("{} B", b) }
    else if b < MB { format!("{:.1} KB", b as f64 / KB as f64) }
    else { format!("{:.1} MB", b as f64 / MB as f64) }
}
