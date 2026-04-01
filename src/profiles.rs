use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerProfile {
    pub name: String,
    pub server: String,
    pub token: String,
    pub internet: bool,
}

fn profiles_path() -> PathBuf {
    let dir = dirs_next().unwrap_or_else(|| PathBuf::from("."));
    dir.join("servers.json")
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
    }
}

pub fn add(profiles: &mut Vec<ServerProfile>, profile: ServerProfile) {
    if let Some(existing) = profiles.iter_mut().find(|p| p.server == profile.server) {
        existing.token = profile.token;
        existing.name = profile.name;
        existing.internet = profile.internet;
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
