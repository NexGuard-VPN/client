/// Per-user "start at login" for the GUI, no elevation required.
/// macOS: LaunchAgent plist. Linux: XDG autostart entry. Windows: HKCU Run key.

pub fn is_enabled() -> bool {
    #[cfg(target_os = "macos")]
    {
        agent_path().map(|p| p.exists()).unwrap_or(false)
    }
    #[cfg(target_os = "linux")]
    {
        desktop_path().map(|p| p.exists()).unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("reg")
            .args(["query", RUN_KEY, "/v", "NexGuard"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

pub fn set_enabled(enabled: bool) -> Result<(), String> {
    if enabled {
        enable()
    } else {
        disable()
    }
}

fn launch_target() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Inside a macOS bundle, launch the .app so LSUIElement and the
    // single-instance socket handshake behave exactly like a manual open.
    if let Some(idx) = exe.find(".app/Contents/MacOS/") {
        return exe[..idx + 4].to_string();
    }
    exe
}

#[cfg(target_os = "macos")]
fn agent_path() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join("Library/LaunchAgents/sh.nexguard.gui.plist"))
}

#[cfg(target_os = "macos")]
fn enable() -> Result<(), String> {
    let target = launch_target();
    let program = if target.ends_with(".app") {
        format!(
            "        <string>/usr/bin/open</string>\n        <string>-a</string>\n        <string>{}</string>",
            target
        )
    } else {
        format!("        <string>{}</string>", target)
    };
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>sh.nexguard.gui</string>
    <key>ProgramArguments</key>
    <array>
{}
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"#,
        program
    );
    let path = agent_path().ok_or("no home dir")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, plist).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn disable() -> Result<(), String> {
    if let Some(path) = agent_path() {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn desktop_path() -> Option<std::path::PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| std::path::PathBuf::from(h).join(".config")))?;
    Some(base.join("autostart/nexguard.desktop"))
}

#[cfg(target_os = "linux")]
fn enable() -> Result<(), String> {
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=NexGuard\nExec={}\nX-GNOME-Autostart-enabled=true\n",
        launch_target()
    );
    let path = desktop_path().ok_or("no config dir")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, entry).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn disable() -> Result<(), String> {
    if let Some(path) = desktop_path() {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(target_os = "windows")]
fn enable() -> Result<(), String> {
    let out = std::process::Command::new("reg")
        .args([
            "add",
            RUN_KEY,
            "/v",
            "NexGuard",
            "/t",
            "REG_SZ",
            "/d",
            &launch_target(),
            "/f",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[cfg(target_os = "windows")]
fn disable() -> Result<(), String> {
    let _ = std::process::Command::new("reg")
        .args(["delete", RUN_KEY, "/v", "NexGuard", "/f"])
        .output();
    Ok(())
}
