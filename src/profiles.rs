use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerProfile {
    pub name: String,
    pub server: String,
    pub token: String,
    pub internet: bool,
    #[serde(default)]
    pub share_lan: bool,
    #[serde(default)]
    pub kill_switch: bool,
}

const PROFILES_FILE: &str = "servers.json";

fn profiles_path() -> PathBuf {
    let dir = crate::dirs_next().unwrap_or_else(|| PathBuf::from("."));
    dir.join(PROFILES_FILE)
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
            || (!p.server.is_empty() && !profile.server.is_empty() && p.server == profile.server)
    });
    if let Some(existing) = existing {
        existing.token = profile.token;
        existing.name = profile.name;
        existing.internet = profile.internet;
        existing.share_lan = profile.share_lan;
        existing.kill_switch = profile.kill_switch;
    } else {
        profiles.push(profile);
    }
    save(profiles);
}

pub fn remove(profiles: &mut Vec<ServerProfile>, index: usize) {
    if index < profiles.len() {
        let removed = profiles.remove(index);
        invalidate_cache(&removed);
        save(profiles);
    }
}

pub fn clear_all(profiles: &mut Vec<ServerProfile>) {
    for profile in profiles.iter() {
        invalidate_cache(profile);
    }
    profiles.clear();
    save(profiles);
}

fn invalidate_cache(profile: &ServerProfile) {
    if !profile.token.is_empty() {
        crate::cache::invalidate(&profile.token);
    }
}
