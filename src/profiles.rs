use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerProfile {
    pub name: String,
    pub server: String,
    pub token: String,
    #[serde(default)]
    pub server_id: String,
    pub internet: bool,
    #[serde(default)]
    pub share_lan: bool,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default)]
    pub last_used: u64,
}

fn profiles_path() -> PathBuf {
    let dir = dirs_next().unwrap_or_else(|| PathBuf::from("."));
    dir.join("servers.json")
}

pub fn config_dir() -> Option<PathBuf> {
    dirs_next()
}

fn dirs_next() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    { std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".nexguard")) }
    #[cfg(target_os = "linux")]
    { std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".nexguard")) }
    #[cfg(target_os = "windows")]
    { std::env::var("APPDATA").ok().map(|h| PathBuf::from(h).join("NexGuard")) }
}

pub fn load() -> Vec<ServerProfile> {
    let path = profiles_path();
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn save(profiles: &[ServerProfile]) {
    let path = profiles_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(profiles) {
        let _ = std::fs::write(&path, json);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

pub fn add(profiles: &mut Vec<ServerProfile>, profile: ServerProfile) {
    let existing = profiles.iter_mut().find(|p| {
        (!p.token.is_empty() && p.token == profile.token)
            || (!p.server_id.is_empty() && !profile.server_id.is_empty() && p.server_id == profile.server_id)
            || (!p.server.is_empty() && !profile.server.is_empty() && p.server == profile.server)
    });
    if let Some(existing) = existing {
        existing.token = profile.token;
        existing.name = profile.name;
        existing.server_id = profile.server_id;
        existing.internet = profile.internet;
        existing.share_lan = profile.share_lan;
        if profile.auto_connect { existing.auto_connect = true; }
    } else {
        profiles.push(profile);
    }
    save(profiles);
}

pub fn remove(profiles: &mut Vec<ServerProfile>, index: usize) {
    if index < profiles.len() {
        profiles.remove(index);
        save(profiles);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(default)]
    pub connection_mode: String,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub dns_leak_protection: bool,
    #[serde(default)]
    pub advertise_routes: String,
    #[serde(default)]
    pub auto_reconnect: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            connection_mode: "auto".to_string(),
            kill_switch: false,
            dns_leak_protection: false,
            advertise_routes: String::new(),
            auto_reconnect: true,
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
