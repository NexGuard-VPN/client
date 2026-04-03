use std::net::Ipv4Addr;

pub struct ExitRouteState {
    preserved_ips: Vec<String>,
    original_gateway: String,
    original_iface: String,
    tun_name: String,
    vpn_dns: Option<String>,
    has_v6: bool,
}

impl ExitRouteState {
    pub fn setup(server_ips: &[&str], tun_name: &str, vpn_network: Option<&str>) -> Result<Self, String> {
        Self::setup_dual(server_ips, tun_name, vpn_network, false)
    }

    pub fn setup_dual(server_ips: &[&str], tun_name: &str, vpn_network: Option<&str>, enable_v6: bool) -> Result<Self, String> {
        let (gw, iface) = detect_default_gateway()?;

        let mut preserved = Vec::new();
        for ip in server_ips {
            if let Ok(()) = add_host_route(ip, &gw, &iface) {
                preserved.push(ip.to_string());
            }
        }

        setup_policy_routing(&gw, &iface);

        if let Err(e) = add_default_via_tun(tun_name) {
            for ip in &preserved {
                remove_host_route(ip, &gw, &iface);
            }
            return Err(e);
        }

        if enable_v6 {
            let _ = add_default_v6_via_tun(tun_name);
        }

        let vpn_dns = vpn_network.and_then(derive_gateway_ip);
        if let Some(ref dns) = vpn_dns {
            set_vpn_dns(dns);
        }

        Ok(Self {
            preserved_ips: preserved,
            original_gateway: gw,
            original_iface: iface,
            tun_name: tun_name.to_owned(),
            vpn_dns,
            has_v6: enable_v6,
        })
    }

    pub fn cleanup(&self) {
        if self.vpn_dns.is_some() {
            restore_dns();
        }
        remove_default_via_tun(&self.tun_name);
        if self.has_v6 {
            remove_default_v6_via_tun(&self.tun_name);
        }
        for ip in &self.preserved_ips {
            remove_host_route(ip, &self.original_gateway, &self.original_iface);
        }
        cleanup_policy_routing();
    }
}

impl Drop for ExitRouteState {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub fn emergency_cleanup(tun_name: &str) {
    eprintln!("[vpn-client] emergency route cleanup for {}", tun_name);
    restore_dns();
    remove_default_via_tun(tun_name);
    remove_default_v6_via_tun(tun_name);
    cleanup_policy_routing();
    if let Ok((gw, _iface)) = detect_default_gateway() {
        if !gw.is_empty() {
            let _ = run_cmd("route", &["delete", "default"]);
            let _ = run_cmd("route", &["add", "default", &gw]);
        }
    }
}

pub fn add_route(net: Ipv4Addr, prefix: u8, tun_name: &str) -> std::io::Result<()> {
    add_route_os(net, prefix, tun_name)
}

pub fn add_route_v6(network: &str, prefix: u8, tun_name: &str) -> std::io::Result<()> {
    add_route_v6_os(network, prefix, tun_name)
}

#[cfg(target_os = "linux")]
fn add_route_v6_os(network: &str, prefix: u8, tun: &str) -> std::io::Result<()> {
    run_cmd("ip", &["-6", "route", "add", &format!("{}/{}", network, prefix), "dev", tun])
        .map_err(|e| std::io::Error::other(e))
}

#[cfg(target_os = "macos")]
fn add_route_v6_os(network: &str, prefix: u8, tun: &str) -> std::io::Result<()> {
    run_cmd("route", &["-n", "add", "-inet6", &format!("{}/{}", network, prefix), "-interface", tun])
        .map_err(|e| std::io::Error::other(e))
}

#[cfg(target_os = "windows")]
fn add_route_v6_os(network: &str, prefix: u8, tun: &str) -> std::io::Result<()> {
    let idx = get_interface_index(tun).unwrap_or_default();
    run_cmd("netsh", &["interface", "ipv6", "add", "route",
        &format!("{}/{}", network, prefix), &format!("interface={}", idx)])
        .map_err(|e| std::io::Error::other(e))
}

#[cfg(target_os = "linux")]
fn detect_default_gateway() -> Result<(String, String), String> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| format!("ip route: {}", e))?;

    let text = String::from_utf8_lossy(&out.stdout);

    let mut gw = None;
    let mut iface = None;
    let parts: Vec<&str> = text.split_whitespace().collect();
    for i in 0..parts.len() {
        if parts[i] == "via" && i + 1 < parts.len() {
            gw = Some(parts[i + 1].to_owned());
        }
        if parts[i] == "dev" && i + 1 < parts.len() {
            iface = Some(parts[i + 1].to_owned());
        }
    }

    match (gw, iface) {
        (Some(g), Some(i)) => Ok((g, i)),
        _ => Err("could not detect default gateway".into()),
    }
}

#[cfg(target_os = "macos")]
fn detect_default_gateway() -> Result<(String, String), String> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("route get default: {}", e))?;

    let text = String::from_utf8_lossy(&out.stdout);
    let mut gw = None;
    let mut iface = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("gateway:") {
            gw = Some(val.trim().to_owned());
        }
        if let Some(val) = trimmed.strip_prefix("interface:") {
            iface = Some(val.trim().to_owned());
        }
    }

    match (gw, iface) {
        (Some(g), Some(i)) => Ok((g, i)),
        _ => Err("could not detect default gateway".into()),
    }
}

#[cfg(target_os = "windows")]
fn detect_default_gateway() -> Result<(String, String), String> {
    let out = std::process::Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .map_err(|e| format!("route print: {}", e))?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
            return Ok((parts[2].to_owned(), parts[3].to_owned()));
        }
    }
    Err("could not detect default gateway".into())
}

#[cfg(target_os = "linux")]
fn add_host_route(ip: &str, gw: &str, iface: &str) -> Result<(), String> {
    run_cmd("ip", &["route", "add", &format!("{}/32", ip), "via", gw, "dev", iface])
}

#[cfg(target_os = "macos")]
fn add_host_route(ip: &str, gw: &str, _iface: &str) -> Result<(), String> {
    run_cmd("route", &["-n", "add", "-host", ip, gw])
}

#[cfg(target_os = "windows")]
fn add_host_route(ip: &str, gw: &str, _iface: &str) -> Result<(), String> {
    run_cmd("route", &["add", ip, "mask", "255.255.255.255", gw, "metric", "1"])
}

#[cfg(target_os = "linux")]
fn add_default_via_tun(tun: &str) -> Result<(), String> {
    run_cmd("ip", &["route", "add", "0.0.0.0/1", "dev", tun])?;
    run_cmd("ip", &["route", "add", "128.0.0.0/1", "dev", tun])
}

#[cfg(target_os = "macos")]
fn add_default_via_tun(tun: &str) -> Result<(), String> {
    run_cmd("route", &["-n", "add", "-net", "0.0.0.0", "-netmask", "128.0.0.0", "-interface", tun])?;
    run_cmd("route", &["-n", "add", "-net", "128.0.0.0", "-netmask", "128.0.0.0", "-interface", tun])
}

#[cfg(target_os = "windows")]
fn add_default_via_tun(tun: &str) -> Result<(), String> {
    let idx = get_interface_index(tun).unwrap_or_default();
    run_cmd("route", &["add", "0.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "if", &idx, "metric", "1"])?;
    run_cmd("route", &["add", "128.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "if", &idx, "metric", "1"])
}

#[cfg(target_os = "linux")]
fn remove_default_via_tun(tun: &str) {
    let _ = run_cmd("ip", &["route", "del", "0.0.0.0/1", "dev", tun]);
    let _ = run_cmd("ip", &["route", "del", "128.0.0.0/1", "dev", tun]);
}

#[cfg(target_os = "macos")]
fn remove_default_via_tun(_tun: &str) {
    let _ = run_cmd("route", &["-n", "delete", "-net", "0.0.0.0", "-netmask", "128.0.0.0"]);
    let _ = run_cmd("route", &["-n", "delete", "-net", "128.0.0.0", "-netmask", "128.0.0.0"]);
}

#[cfg(target_os = "windows")]
fn remove_default_via_tun(_tun: &str) {
    let _ = run_cmd("route", &["delete", "0.0.0.0", "mask", "128.0.0.0"]);
    let _ = run_cmd("route", &["delete", "128.0.0.0", "mask", "128.0.0.0"]);
}

#[cfg(target_os = "linux")]
fn add_default_v6_via_tun(tun: &str) -> Result<(), String> {
    run_cmd("ip", &["-6", "route", "add", "::/1", "dev", tun])?;
    run_cmd("ip", &["-6", "route", "add", "8000::/1", "dev", tun])
}

#[cfg(target_os = "macos")]
fn add_default_v6_via_tun(tun: &str) -> Result<(), String> {
    run_cmd("route", &["-n", "add", "-inet6", "::/1", "-interface", tun])?;
    run_cmd("route", &["-n", "add", "-inet6", "8000::/1", "-interface", tun])
}

#[cfg(target_os = "windows")]
fn add_default_v6_via_tun(tun: &str) -> Result<(), String> {
    let idx = get_interface_index(tun).unwrap_or_default();
    run_cmd("netsh", &["interface", "ipv6", "add", "route", "::/1", &format!("interface={}", idx), "metric=1"])?;
    run_cmd("netsh", &["interface", "ipv6", "add", "route", "8000::/1", &format!("interface={}", idx), "metric=1"])
}

#[cfg(target_os = "linux")]
fn remove_default_v6_via_tun(tun: &str) {
    let _ = run_cmd("ip", &["-6", "route", "del", "::/1", "dev", tun]);
    let _ = run_cmd("ip", &["-6", "route", "del", "8000::/1", "dev", tun]);
}

#[cfg(target_os = "macos")]
fn remove_default_v6_via_tun(_tun: &str) {
    let _ = run_cmd("route", &["-n", "delete", "-inet6", "::/1"]);
    let _ = run_cmd("route", &["-n", "delete", "-inet6", "8000::/1"]);
}

#[cfg(target_os = "windows")]
fn remove_default_v6_via_tun(tun: &str) {
    let idx = get_interface_index(tun).unwrap_or_default();
    let _ = run_cmd("netsh", &["interface", "ipv6", "delete", "route", "::/1", &format!("interface={}", idx)]);
    let _ = run_cmd("netsh", &["interface", "ipv6", "delete", "route", "8000::/1", &format!("interface={}", idx)]);
}

#[cfg(target_os = "linux")]
fn remove_host_route(ip: &str, gw: &str, _iface: &str) {
    let _ = run_cmd("ip", &["route", "del", &format!("{}/32", ip), "via", gw]);
}

#[cfg(target_os = "macos")]
fn remove_host_route(ip: &str, _gw: &str, _iface: &str) {
    let _ = run_cmd("route", &["-n", "delete", "-host", ip]);
}

#[cfg(target_os = "windows")]
fn remove_host_route(ip: &str, _gw: &str, _iface: &str) {
    let _ = run_cmd("route", &["delete", ip]);
}

#[cfg(target_os = "linux")]
fn add_route_os(net: Ipv4Addr, prefix: u8, tun: &str) -> std::io::Result<()> {
    run_cmd("ip", &["route", "add", &format!("{}/{}", net, prefix), "dev", tun])
        .map_err(|e| std::io::Error::other(e))
}

#[cfg(target_os = "macos")]
fn add_route_os(net: Ipv4Addr, prefix: u8, tun: &str) -> std::io::Result<()> {
    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    let mask_ip = Ipv4Addr::from(mask);
    run_cmd("route", &[
        "-n", "add", "-net", &net.to_string(),
        "-netmask", &mask_ip.to_string(),
        "-interface", tun,
    ]).map_err(|e| std::io::Error::other(e))
}

#[cfg(target_os = "windows")]
fn add_route_os(net: Ipv4Addr, prefix: u8, tun: &str) -> std::io::Result<()> {
    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    let mask_ip = Ipv4Addr::from(mask);
    let idx = get_interface_index(tun).unwrap_or_default();
    run_cmd("route", &["add", &net.to_string(), "mask", &mask_ip.to_string(), "0.0.0.0", "if", &idx])
        .map_err(|e| std::io::Error::other(e))
}

#[cfg(target_os = "linux")]
fn setup_policy_routing(gw: &str, iface: &str) {
    if let Some(src_ip) = detect_source_ip(iface) {
        let _ = run_cmd("ip", &["rule", "add", "from", &src_ip, "table", "100"]);
        let _ = run_cmd("ip", &["route", "add", "default", "via", gw, "dev", iface, "table", "100"]);
    }
}

#[cfg(target_os = "macos")]
fn setup_policy_routing(_gw: &str, _iface: &str) {}

#[cfg(target_os = "windows")]
fn setup_policy_routing(_gw: &str, _iface: &str) {}

#[cfg(target_os = "windows")]
fn get_interface_index(name: &str) -> Option<String> {
    let out = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.contains(name) {
            return line.split_whitespace().next().map(|s| s.to_owned());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn cleanup_policy_routing() {
    let _ = run_cmd("ip", &["rule", "del", "table", "100"]);
    let _ = run_cmd("ip", &["route", "flush", "table", "100"]);
}

#[cfg(target_os = "macos")]
fn cleanup_policy_routing() {}

#[cfg(target_os = "windows")]
fn cleanup_policy_routing() {}

#[cfg(target_os = "linux")]
fn detect_source_ip(iface: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["addr", "show", iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(ip) = rest.split('/').next() {
                return Some(ip.to_owned());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn detect_source_ip(iface: &str) -> Option<String> {
    let out = std::process::Command::new("ifconfig")
        .arg(iface)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            return rest.split_whitespace().next().map(|s| s.to_owned());
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn detect_source_ip(_iface: &str) -> Option<String> { None }

fn derive_gateway_ip(network: &str) -> Option<String> {
    let (ip_str, _) = network.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let octets = ip.octets();
    Some(format!("{}.{}.{}.1", octets[0], octets[1], octets[2]))
}

#[cfg(target_os = "linux")]
fn set_vpn_dns(vpn_server_ip: &str) {
    let _ = std::fs::copy("/etc/resolv.conf", "/etc/resolv.conf.vpn-backup");
    let _ = std::fs::write("/etc/resolv.conf", format!("nameserver {}\n", vpn_server_ip));
}

#[cfg(target_os = "linux")]
fn restore_dns() {
    if std::path::Path::new("/etc/resolv.conf.vpn-backup").exists() {
        let _ = std::fs::copy("/etc/resolv.conf.vpn-backup", "/etc/resolv.conf");
        let _ = std::fs::remove_file("/etc/resolv.conf.vpn-backup");
    }
}

#[cfg(target_os = "macos")]
fn set_vpn_dns(vpn_server_ip: &str) {
    let _ = run_cmd("networksetup", &["-setdnsservers", "Wi-Fi", vpn_server_ip]);
}

#[cfg(target_os = "macos")]
fn restore_dns() {
    let _ = run_cmd("networksetup", &["-setdnsservers", "Wi-Fi", "empty"]);
}

#[cfg(target_os = "windows")]
fn set_vpn_dns(vpn_server_ip: &str) {
    let _ = run_cmd("netsh", &["interface", "ipv4", "set", "dnsservers",
        "name=NexGuard", "static", vpn_server_ip, "primary"]);
}

#[cfg(target_os = "windows")]
fn restore_dns() {
    let _ = run_cmd("netsh", &["interface", "ipv4", "set", "dnsservers",
        "name=NexGuard", "dhcp"]);
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| format!("{} {}: {}", cmd, args.join(" "), e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("{} {} failed ({})", cmd, args.join(" "), status))
    }
}
