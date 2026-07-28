use std::path::PathBuf;
use std::sync::OnceLock;

#[cfg(windows)]
const STORAGE_DIR_NAME: &str = "NexGuard";
#[cfg(not(windows))]
const STORAGE_DIR_NAME: &str = ".nexguard";

static STORAGE_DIR: OnceLock<PathBuf> = OnceLock::new();

#[allow(dead_code)]
pub fn set_storage_dir(path: PathBuf) {
    let _ = STORAGE_DIR.set(path);
}

#[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
fn sudo_user_home() -> Option<String> {
    let user = std::env::var("SUDO_USER").ok()?;
    if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return None;
    }
    let out = std::process::Command::new("getent")
        .args(["passwd", &user])
        .output()
        .ok()?;
    let line = String::from_utf8_lossy(&out.stdout);
    let home = line.split(':').nth(5)?.trim().to_string();
    if home.is_empty() { None } else { Some(home) }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn sudo_user_home() -> Option<String> {
    None
}

fn base_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("APPDATA")
            .ok()
            .or_else(|| std::env::var("USERPROFILE").ok())
            .map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        sudo_user_home()
            .or_else(|| std::env::var("HOME").ok())
            .map(PathBuf::from)
    }
}

pub fn storage_dir() -> Option<PathBuf> {
    let dir = match STORAGE_DIR.get() {
        Some(dir) => dir.clone(),
        None => base_dir()?.join(STORAGE_DIR_NAME),
    };
    std::fs::create_dir_all(&dir).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Some(dir)
}
