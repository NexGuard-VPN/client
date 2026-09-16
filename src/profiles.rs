use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn config_dir() -> Option<PathBuf> {
    dirs_next()
}

#[cfg(unix)]
const APP_DIR_UNIX: &str = ".nexguard";
#[cfg(windows)]
const APP_DIR_WINDOWS: &str = "NexGuard";

/// Looks the account up in the passwd database directly: a launchd daemon has
/// no HOME, and macOS has no `getent`.
#[cfg(unix)]
pub(crate) fn passwd_home(key: &str) -> Option<String> {
    let entry = match key.parse::<u32>() {
        Ok(uid) => unsafe { libc::getpwuid(uid) },
        Err(_) => {
            let name = std::ffi::CString::new(key).ok()?;
            unsafe { libc::getpwnam(name.as_ptr()) }
        }
    };
    if entry.is_null() {
        return None;
    }
    let dir = unsafe { (*entry).pw_dir };
    if dir.is_null() {
        return None;
    }
    let home = unsafe { std::ffi::CStr::from_ptr(dir) }.to_string_lossy().trim().to_string();
    (!home.is_empty()).then_some(home)
}

/// The per-user state directory of another account, for the daemon to adopt
/// what the app used to keep there when it still ran as that user.
#[cfg(unix)]
pub(crate) fn user_config_dir(uid: u32) -> Option<PathBuf> {
    passwd_home(&uid.to_string()).map(|home| PathBuf::from(home).join(APP_DIR_UNIX))
}

#[cfg(unix)]
fn sudo_home() -> Option<String> {
    let user = std::env::var("SUDO_USER").ok().filter(|u| {
        u.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    })?;
    passwd_home(&user)
}

fn dirs_next() -> Option<PathBuf> {
    #[cfg(unix)]
    let base = sudo_home()
        .or_else(|| std::env::var("HOME").ok().filter(|h| !h.is_empty()))
        .or_else(|| passwd_home(&unsafe { libc::getuid() }.to_string()))?;
    #[cfg(unix)]
    let dir = PathBuf::from(base).join(APP_DIR_UNIX);

    #[cfg(windows)]
    let dir = PathBuf::from(std::env::var("APPDATA").ok()?).join(APP_DIR_WINDOWS);

    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(default)]
    pub advertise_routes: String,
    #[serde(default)]
    pub auto_reconnect: bool,
    #[serde(default)]
    pub mesh_exit_node: String,
    #[serde(default)]
    pub mesh_advertise_exit_node: bool,
    #[serde(default)]
    pub mesh_network_id: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub api_host: String,
    #[serde(default)]
    pub mesh_magic_dns: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            advertise_routes: String::new(),
            auto_reconnect: true,
            mesh_exit_node: String::new(),
            mesh_advertise_exit_node: false,
            mesh_network_id: String::new(),
            project_id: String::new(),
            api_host: String::new(),
            mesh_magic_dns: false,
        }
    }
}

fn settings_path() -> PathBuf {
    dirs_next().unwrap_or_else(|| PathBuf::from(".")).join("settings.json")
}

pub fn load_settings() -> AppSettings {
    match std::fs::read_to_string(settings_path()) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => AppSettings::default(),
    }
}

pub fn save_settings(settings: &AppSettings) {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(settings) {
        let _ = std::fs::write(&path, json);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}
