pub fn collect() -> String {
    let parts = vec![
        machine_id(),
        mac_address(),
        cpu_model(),
        hostname(),
    ];
    parts.join("|")
}

pub fn hmac_fingerprint(fingerprint: &str, secret: &str) -> String {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .unwrap_or_else(|_| <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(b"nexguard").unwrap());
    mac.update(fingerprint.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

#[cfg(target_os = "macos")]
fn machine_id() -> String {
    let out = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok();
    if let Some(out) = out {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(uuid) = line.split('"').nth(3) {
                    return uuid.to_string();
                }
            }
        }
    }
    String::new()
}

#[cfg(target_os = "linux")]
fn machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[cfg(target_os = "windows")]
fn machine_id() -> String {
    let out = std::process::Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        .output()
        .ok();
    if let Some(out) = out {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if line.contains("MachineGuid") {
                if let Some(guid) = line.split_whitespace().last() {
                    return guid.to_string();
                }
            }
        }
    }
    String::new()
}

#[cfg(target_os = "macos")]
fn mac_address() -> String {
    let out = std::process::Command::new("ifconfig")
        .args(["en0"])
        .output()
        .ok();
    if let Some(out) = out {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("ether ") {
                return trimmed[6..].trim().to_string();
            }
        }
    }
    String::new()
}

#[cfg(target_os = "linux")]
fn mac_address() -> String {
    for iface in &["eth0", "ens3", "enp0s3", "wlan0"] {
        let path = format!("/sys/class/net/{}/address", iface);
        if let Ok(mac) = std::fs::read_to_string(&path) {
            let mac = mac.trim().to_string();
            if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                return mac;
            }
        }
    }
    String::new()
}

#[cfg(target_os = "windows")]
fn mac_address() -> String {
    let out = std::process::Command::new("getmac")
        .args(["/fo", "csv", "/nh"])
        .output()
        .ok();
    if let Some(out) = out {
        let s = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = s.lines().next() {
            if let Some(mac) = line.split(',').next() {
                return mac.replace('"', "").trim().to_string();
            }
        }
    }
    String::new()
}

fn cpu_model() -> String {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok();
        if let Some(out) = out {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in info.lines() {
                if line.starts_with("model name") {
                    if let Some(model) = line.split(':').nth(1) {
                        return model.trim().to_string();
                    }
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("wmic")
            .args(["cpu", "get", "name", "/value"])
            .output()
            .ok();
        if let Some(out) = out {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                if line.starts_with("Name=") {
                    return line[5..].trim().to_string();
                }
            }
        }
    }
    String::new()
}

fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
        if ret == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            return String::from_utf8_lossy(&buf[..end]).to_string();
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(h) = std::env::var("COMPUTERNAME") {
            return h;
        }
    }
    String::new()
}
