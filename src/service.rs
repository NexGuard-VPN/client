use crate::cli::service_args;

#[cfg(target_os = "macos")]
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/sh.nexguard.vpn.plist";
#[cfg(target_os = "macos")]
const LAUNCHD_LOG: &str = "/var/log/nexguard.log";
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT: &str = "/etc/systemd/system/nexguard.service";
#[cfg(target_os = "linux")]
const SYSTEMD_NAME: &str = "nexguard";
pub const INSTALL_FLAG: &str = "--install-service";
pub const UNINSTALL_FLAG: &str = "--uninstall-service";

fn exe_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .expect("current exe")
}

/// The uid that asked for the install, so the daemon later lets that user's
/// own session drive it without root.
fn operator_uid() -> Option<String> {
    ["PKEXEC_UID", "SUDO_UID"]
        .iter()
        .find_map(|key| std::env::var(key).ok())
        .filter(|v| v.parse::<u32>().is_ok())
}

pub fn install(args: &[String]) {
    let exe = exe_path();
    let cli_args = service_args(args);
    write_unit(&exe, &cli_args);
    eprintln!("[nexguard] service installed — auto-starts on boot");
    eprintln!("[nexguard] to uninstall: sudo nexguard {}", UNINSTALL_FLAG);
}

#[cfg(target_os = "macos")]
fn write_unit(exe: &str, cli_args: &[String]) {
    let operator = operator_uid()
        .map(|uid| {
            format!(
                "\n    <key>EnvironmentVariables</key>\n    <dict><key>{}</key><string>{}</string></dict>",
                crate::control::OPERATOR_UID_ENV,
                uid
            )
        })
        .unwrap_or_default();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>sh.nexguard.vpn</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>{}
    </array>{}
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{}</string>
    <key>StandardErrorPath</key>
    <string>{}</string>
</dict>
</plist>"#,
        exe,
        cli_args.iter().map(|a| format!("\n        <string>{}</string>", a)).collect::<String>(),
        operator,
        LAUNCHD_LOG,
        LAUNCHD_LOG,
    );
    let _ = std::process::Command::new("launchctl").args(["unload", LAUNCHD_PLIST]).status();
    std::fs::write(LAUNCHD_PLIST, plist).expect("write plist");
    let _ = std::process::Command::new("launchctl").args(["load", "-w", LAUNCHD_PLIST]).status();
}

#[cfg(target_os = "linux")]
fn write_unit(exe: &str, cli_args: &[String]) {
    let operator = operator_uid()
        .map(|uid| format!("Environment={}={}\n", crate::control::OPERATOR_UID_ENV, uid))
        .unwrap_or_default();
    let unit = format!(
        r#"[Unit]
Description=NexGuard Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
{}ExecStart={} {}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"#,
        operator,
        exe,
        cli_args.join(" ")
    );
    std::fs::write(SYSTEMD_UNIT, unit).expect("write service");
    let _ = std::process::Command::new("systemctl").args(["daemon-reload"]).status();
    let _ = std::process::Command::new("systemctl").args(["enable", SYSTEMD_NAME]).status();
    let _ = std::process::Command::new("systemctl").args(["restart", SYSTEMD_NAME]).status();
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn write_unit(_exe: &str, _cli_args: &[String]) {
    eprintln!("[nexguard] boot service is not supported on this platform");
}

pub fn uninstall() {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("launchctl").args(["unload", "-w", LAUNCHD_PLIST]).status();
        let _ = std::fs::remove_file(LAUNCHD_PLIST);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl").args(["disable", "--now", SYSTEMD_NAME]).status();
        let _ = std::fs::remove_file(SYSTEMD_UNIT);
        let _ = std::process::Command::new("systemctl").args(["daemon-reload"]).status();
    }
    eprintln!("[nexguard] service removed");
}

/// Asks the desktop for administrator rights once and installs the daemon
/// from the running binary, so the GUI itself never has to be root.
#[cfg(all(feature = "gui", target_os = "macos"))]
pub fn install_elevated() -> Result<(), String> {
    let exe = exe_path();
    let script = format!(
        "do shell script \"'{}' {}\" with administrator privileges",
        exe.replace('\'', "'\\\\''"),
        INSTALL_FLAG
    );
    run_elevated(std::process::Command::new("osascript").args(["-e", &script]))
}

#[cfg(all(feature = "gui", target_os = "linux"))]
pub fn install_elevated() -> Result<(), String> {
    run_elevated(std::process::Command::new("pkexec").args([exe_path(), INSTALL_FLAG.to_string()]))
}

#[cfg(all(feature = "gui", any(target_os = "macos", target_os = "linux")))]
fn run_elevated(cmd: &mut std::process::Command) -> Result<(), String> {
    let output = cmd.output().map_err(|e| format!("elevation failed: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if detail.is_empty() { "install was cancelled".into() } else { detail })
    }
}
