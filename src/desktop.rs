pub const DISPLAY_VARS: [&str; 2] = ["WAYLAND_DISPLAY", "DISPLAY"];
pub const LINUX: &str = "linux";
pub const LINUX_DESKTOP: &str = "linux-desktop";

pub fn has_display(lookup: impl Fn(&str) -> Option<String>) -> bool {
    DISPLAY_VARS
        .iter()
        .any(|var| lookup(var).is_some_and(|value| !value.trim().is_empty()))
}

pub fn session_has_display() -> bool {
    !cfg!(target_os = "linux") || has_display(|var| std::env::var(var).ok())
}

pub fn update_platform(os: &str, arch: &str, desktop: bool) -> String {
    let flavor = if os == LINUX && desktop { LINUX_DESKTOP } else { os };
    format!("{}-{}", flavor, arch)
}
