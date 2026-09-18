use crate::{profiles, rng};

pub const KEY_FILE: &str = "client.key";

fn key_path() -> std::path::PathBuf {
    let dir = dirs_next().unwrap_or_else(|| std::path::PathBuf::from("."));
    dir.join(KEY_FILE)
}

pub fn dirs_next() -> Option<std::path::PathBuf> {
    profiles::config_dir()
}

pub fn load_or_generate_key() -> [u8; 32] {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let path = key_path();

    let try_load = |p: &std::path::Path| -> Option<[u8; 32]> {
        let data = std::fs::read_to_string(p).ok()?;
        let bytes = b64.decode(data.trim()).ok()?;
        if bytes.len() != 32 { return None; }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Some(key)
    };

    if let Some(key) = try_load(&path) {
        secure_key_file(&path);
        return key;
    }

    #[cfg(unix)]
    {
        let root_path = std::path::PathBuf::from(LEGACY_ROOT_KEY);
        if root_path != path {
            if let Some(key) = try_load(&root_path) {
                let _ = std::fs::write(&path, b64.encode(key));
                secure_key_file(&path);
                let _ = std::fs::remove_file(&root_path);
                return key;
            }
        }
    }

    let key = generate_private_key();
    let _ = std::fs::write(&path, b64.encode(key));
    secure_key_file(&path);
    key
}

#[cfg(unix)]
const LEGACY_ROOT_KEY: &str = "/var/root/.nexguard/client.key";

fn secure_key_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        fix_ownership(path);
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(unix)]
fn fix_ownership(path: &std::path::Path) {
    if let Ok(user) = std::env::var("SUDO_USER") {
        let _ = std::process::Command::new("chown")
            .args([&user, &path.to_string_lossy().to_string()])
            .status();
        if let Some(dir) = path.parent() {
            let _ = std::process::Command::new("chown")
                .args([&user, &dir.to_string_lossy().to_string()])
                .status();
        }
    }
}

pub fn generate_private_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rng::fill(&mut key);
    key
}

pub fn b64_encode(d: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(d)
}

pub fn generate_client_name() -> String {
    std::env::var("VPN_NAME").unwrap_or_else(|_| {
        let id_path = dirs_next()
            .map(|d| d.join("device-id"))
            .unwrap_or_else(|| std::path::PathBuf::from(".nexguard-device-id"));

        if let Ok(id) = std::fs::read_to_string(&id_path) {
            let id = id.trim().to_string();
            if !id.is_empty() { return id; }
        }

        #[cfg(unix)]
        {
            let root_id = std::path::PathBuf::from("/var/root/.nexguard/device-id");
            if root_id != id_path {
                if let Ok(id) = std::fs::read_to_string(&root_id) {
                    let id = id.trim().to_string();
                    if !id.is_empty() {
                        let _ = std::fs::write(&id_path, &id);
                        let _ = std::fs::remove_file(&root_id);
                        return id;
                    }
                }
            }
        }

        let hostname = get_hostname();
        let os_name = if cfg!(target_os = "macos") { "mac" }
            else if cfg!(target_os = "windows") { "win" }
            else { "linux" };

        let mut seed = [0u8; 4];
        #[cfg(unix)]
        {
            let fd = unsafe { libc::open(b"/dev/urandom\0".as_ptr() as *const _, libc::O_RDONLY) };
            if fd >= 0 {
                unsafe { libc::read(fd, seed.as_mut_ptr() as *mut _, 4); libc::close(fd); }
            }
        }
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Security::Cryptography::*;
            unsafe { BCryptGenRandom(std::ptr::null_mut(), seed.as_mut_ptr(), 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG); }
        }

        let name = format!("{}-{}-{:02x}{:02x}", hostname, os_name, seed[0], seed[1]);
        let _ = std::fs::write(&id_path, &name);
        #[cfg(unix)]
        fix_ownership(&id_path);
        name
    })
}

fn get_hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
        if ret == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let h = String::from_utf8_lossy(&buf[..end]).to_string();
            if !h.is_empty() { return h; }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(h) = std::env::var("COMPUTERNAME") { return h; }
    }
    "device".to_string()
}
