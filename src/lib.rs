use std::path::PathBuf;

#[path = "paths.rs"]
pub mod paths;
#[path = "tun.rs"]
pub mod tun;
#[path = "fingerprint.rs"]
pub mod fingerprint;
#[path = "cache.rs"]
pub mod cache;
#[path = "api.rs"]
pub mod api;
#[path = "mesh.rs"]
pub mod mesh;
#[path = "wg.rs"]
pub mod wg;

pub mod ffi;
#[cfg(target_os = "android")]
mod android;

pub fn set_storage_dir(path: PathBuf) {
    paths::set_storage_dir(path);
}

pub fn dirs_next() -> Option<PathBuf> {
    paths::storage_dir()
}

pub fn generate_private_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("CSPRNG unavailable");
    key
}

pub fn jittered_keepalive() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u16;
    18 + (nanos % 15)
}

pub fn b64_encode(d: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(d)
}

pub fn b64_decode_32(s: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&b);
    Some(k)
}
