use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CACHE_TTL_SECS: u64 = 1800;
const CACHE_FILE: &str = "connect-cache.json";
const MAX_ENTRIES: usize = 10;

#[derive(Serialize, Deserialize, Clone)]
pub struct CacheEntry {
    pub token_hash: String,
    pub server: Option<String>,
    pub relay: Option<String>,
    pub relay_name: Option<String>,
    pub join_url: Option<String>,
    pub join_response: serde_json::Value,
    pub cached_at: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct CacheFile {
    entries: Vec<CacheEntry>,
}

pub fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(&hasher.finalize()[..16])
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_path() -> Option<std::path::PathBuf> {
    crate::dirs_next().map(|d| d.join(CACHE_FILE))
}

pub fn load(token: &str) -> Option<CacheEntry> {
    let path = cache_path()?;
    let data = std::fs::read_to_string(&path).ok()?;
    let file: CacheFile = serde_json::from_str(&data).ok()?;
    let now = now_secs();
    let hash = token_hash(token);
    file.entries.into_iter().find(|e| {
        e.token_hash == hash && now.saturating_sub(e.cached_at) < CACHE_TTL_SECS
    })
}

pub fn save(
    token: &str,
    server: Option<String>,
    relay: Option<String>,
    relay_name: Option<String>,
    join_url: Option<String>,
    join_response: serde_json::Value,
) {
    let Some(path) = cache_path() else { return };
    let mut file: CacheFile = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let hash = token_hash(token);
    file.entries.retain(|e| e.token_hash != hash);
    file.entries.push(CacheEntry {
        token_hash: hash,
        server,
        relay,
        relay_name,
        join_url,
        join_response,
        cached_at: now_secs(),
    });
    if file.entries.len() > MAX_ENTRIES {
        let drain_end = file.entries.len() - MAX_ENTRIES;
        file.entries.drain(0..drain_end);
    }
    if let Ok(s) = serde_json::to_string(&file) {
        let _ = std::fs::write(&path, s);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

pub fn invalidate(token: &str) {
    let Some(path) = cache_path() else { return };
    let Ok(data) = std::fs::read_to_string(&path) else { return };
    let Ok(mut file) = serde_json::from_str::<CacheFile>(&data) else { return };
    let hash = token_hash(token);
    let before = file.entries.len();
    file.entries.retain(|e| e.token_hash != hash);
    if file.entries.len() != before {
        if let Ok(s) = serde_json::to_string(&file) {
            let _ = std::fs::write(&path, s);
        }
    }
}
