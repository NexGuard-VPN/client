use std::io::Write;
use std::net::Ipv4Addr;

const DNS_STATE_FILE: &str = "dns-restore.json";

#[cfg(target_os = "macos")]
const DNS_MACOS_CLEAR: &str = "empty";

#[cfg(target_os = "windows")]
const DNS_WINDOWS_DHCP: &str = "dhcp";

pub struct ExitRouteState {
    preserved_ips: Vec<String>,
    original_gateway: String,
    original_iface: String,
    tun_name: String,
    has_v6: bool,
    v6_blackhole: bool,
}

impl ExitRouteState {
    pub fn setup_dual(server_ips: &[&str], tun_name: &str, enable_v6: bool) -> Result<Self, String> {
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

        let mut v6_blackhole = false;
        if enable_v6 {
            let _ = add_default_v6_via_tun(tun_name);
        } else {
            v6_blackhole = add_v6_blackhole(tun_name).is_ok();
        }

        Ok(Self {
            preserved_ips: preserved,
            original_gateway: gw,
            original_iface: iface,
            tun_name: tun_name.to_owned(),
            has_v6: enable_v6,
            v6_blackhole,
        })
    }

    pub fn cleanup(&self) {
        remove_default_via_tun(&self.tun_name);
        if self.has_v6 {
            remove_default_v6_via_tun(&self.tun_name);
        }
        if self.v6_blackhole {
            remove_v6_blackhole(&self.tun_name);
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
    let _ = writeln!(std::io::stderr(), "[vpn-client] emergency route cleanup for {}", tun_name);
    remove_default_via_tun(tun_name);
    remove_default_v6_via_tun(tun_name);
    remove_v6_blackhole(tun_name);
    cleanup_policy_routing();
    restore_orphaned_dns();
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
fn add_v6_blackhole(_tun: &str) -> Result<(), String> {
    run_cmd("ip", &["-6", "route", "add", "blackhole", "::/1", "metric", "1"])?;
    run_cmd("ip", &["-6", "route", "add", "blackhole", "8000::/1", "metric", "1"])
}

#[cfg(target_os = "macos")]
fn add_v6_blackhole(_tun: &str) -> Result<(), String> {
    run_cmd("route", &["-n", "add", "-inet6", "-blackhole", "::/1", "::1"])?;
    run_cmd("route", &["-n", "add", "-inet6", "-blackhole", "8000::/1", "::1"])
}

#[cfg(target_os = "windows")]
fn add_v6_blackhole(tun: &str) -> Result<(), String> {
    let idx = get_interface_index(tun).unwrap_or_default();
    run_cmd("netsh", &["interface", "ipv6", "add", "route", "::/1", &format!("interface={}", idx), "metric=1"])?;
    run_cmd("netsh", &["interface", "ipv6", "add", "route", "8000::/1", &format!("interface={}", idx), "metric=1"])
}

#[cfg(target_os = "linux")]
fn remove_v6_blackhole(_tun: &str) {
    let _ = run_cmd("ip", &["-6", "route", "del", "blackhole", "::/1"]);
    let _ = run_cmd("ip", &["-6", "route", "del", "blackhole", "8000::/1"]);
}

#[cfg(target_os = "macos")]
fn remove_v6_blackhole(_tun: &str) {
    let _ = run_cmd("route", &["-n", "delete", "-inet6", "::/1"]);
    let _ = run_cmd("route", &["-n", "delete", "-inet6", "8000::/1"]);
}

#[cfg(target_os = "windows")]
fn remove_v6_blackhole(tun: &str) {
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

pub struct KillSwitch {
    enabled: bool,
}

impl KillSwitch {
    pub fn activate(tun_name: &str, server_ips: &[&str]) -> Self {
        if let Err(e) = activate_kill_switch(tun_name, server_ips) {
            let _ = writeln!(std::io::stderr(), "[vpn-client] kill switch failed: {}", e);
            return Self { enabled: false };
        }
        let _ = writeln!(std::io::stderr(), "[vpn-client] kill switch enabled");
        Self { enabled: true }
    }

    pub fn deactivate(&self) {
        if self.enabled {
            deactivate_kill_switch();
            let _ = writeln!(std::io::stderr(), "[vpn-client] kill switch disabled");
        }
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        self.deactivate();
    }
}

#[cfg(target_os = "macos")]
fn activate_kill_switch(tun_name: &str, server_ips: &[&str]) -> Result<(), String> {
    let mut rules = String::new();
    rules.push_str("# NexGuard kill switch\n");
    rules.push_str("block drop all\n");
    rules.push_str(&format!("pass on {} all\n", tun_name));
    rules.push_str("pass on lo0 all\n");
    for ip in server_ips {
        rules.push_str(&format!("pass out proto tcp to {} port 443\n", ip));
        rules.push_str(&format!("pass out proto tcp to {} port 9190\n", ip));
    }
    rules.push_str("pass out proto udp to any port 53\n");
    rules.push_str("pass out proto tcp to any port 53\n");

    std::fs::write("/tmp/nexguard-pf.conf", &rules)
        .map_err(|e| format!("write pf rules: {}", e))?;
    run_cmd("pfctl", &["-f", "/tmp/nexguard-pf.conf"])
        .map_err(|e| format!("pfctl load: {}", e))?;
    run_cmd("pfctl", &["-e"]).ok();
    Ok(())
}

#[cfg(target_os = "macos")]
fn deactivate_kill_switch() {
    let _ = run_cmd("pfctl", &["-d"]);
    let _ = std::fs::remove_file("/tmp/nexguard-pf.conf");
}

#[cfg(target_os = "linux")]
fn activate_kill_switch(tun_name: &str, server_ips: &[&str]) -> Result<(), String> {
    run_cmd("iptables", &["-N", "NEXGUARD-KS"]).ok();
    run_cmd("iptables", &["-F", "NEXGUARD-KS"])?;
    run_cmd("iptables", &["-A", "NEXGUARD-KS", "-o", tun_name, "-j", "ACCEPT"])?;
    run_cmd("iptables", &["-A", "NEXGUARD-KS", "-o", "lo", "-j", "ACCEPT"])?;
    run_cmd("iptables", &["-A", "NEXGUARD-KS", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
    for ip in server_ips {
        run_cmd("iptables", &["-A", "NEXGUARD-KS", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "ACCEPT"])?;
        run_cmd("iptables", &["-A", "NEXGUARD-KS", "-d", ip, "-p", "tcp", "--dport", "9190", "-j", "ACCEPT"])?;
    }
    run_cmd("iptables", &["-A", "NEXGUARD-KS", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])?;
    run_cmd("iptables", &["-A", "NEXGUARD-KS", "-j", "DROP"])?;
    run_cmd("iptables", &["-I", "OUTPUT", "1", "-j", "NEXGUARD-KS"])?;

    run_cmd("ip6tables", &["-N", "NEXGUARD-KS6"]).ok();
    run_cmd("ip6tables", &["-F", "NEXGUARD-KS6"])?;
    run_cmd("ip6tables", &["-A", "NEXGUARD-KS6", "-o", tun_name, "-j", "ACCEPT"])?;
    run_cmd("ip6tables", &["-A", "NEXGUARD-KS6", "-o", "lo", "-j", "ACCEPT"])?;
    run_cmd("ip6tables", &["-A", "NEXGUARD-KS6", "-j", "DROP"])?;
    run_cmd("ip6tables", &["-I", "OUTPUT", "1", "-j", "NEXGUARD-KS6"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn deactivate_kill_switch() {
    let _ = run_cmd("iptables", &["-D", "OUTPUT", "-j", "NEXGUARD-KS"]);
    let _ = run_cmd("iptables", &["-F", "NEXGUARD-KS"]);
    let _ = run_cmd("iptables", &["-X", "NEXGUARD-KS"]);
    let _ = run_cmd("ip6tables", &["-D", "OUTPUT", "-j", "NEXGUARD-KS6"]);
    let _ = run_cmd("ip6tables", &["-F", "NEXGUARD-KS6"]);
    let _ = run_cmd("ip6tables", &["-X", "NEXGUARD-KS6"]);
}

#[cfg(target_os = "windows")]
fn activate_kill_switch(_tun_name: &str, _server_ips: &[&str]) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn deactivate_kill_switch() {}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("{} {}: {}", cmd, args.join(" "), e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{} {} failed ({}) {}", cmd, args.join(" "), output.status, stderr.trim()))
    }
}

pub fn detect_local_subnets() -> Vec<String> {
    let mut subnets = Vec::new();
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("route").args(["-n", "get", "default"]).output() {
            let s = String::from_utf8_lossy(&output.stdout);
            let mut iface = String::new();
            for line in s.lines() {
                if let Some(rest) = line.trim().strip_prefix("interface:") {
                    iface = rest.trim().to_string();
                }
            }
            if !iface.is_empty() {
                if let Ok(out) = std::process::Command::new("ifconfig").arg(&iface).output() {
                    let s = String::from_utf8_lossy(&out.stdout);
                    for line in s.lines() {
                        let line = line.trim();
                        if let Some(rest) = line.strip_prefix("inet ") {
                            let parts: Vec<&str> = rest.split_whitespace().collect();
                            if parts.len() >= 4 && parts[2] == "netmask" {
                                let ip = parts[0];
                                let netmask = parts[3].trim_start_matches("0x");
                                if let Ok(mask) = u32::from_str_radix(netmask, 16) {
                                    let prefix = mask.count_ones();
                                    if let Ok(ip_addr) = ip.parse::<std::net::Ipv4Addr>() {
                                        let net_u32 = u32::from(ip_addr) & mask;
                                        let net = std::net::Ipv4Addr::from(net_u32);
                                        if !ip_addr.is_loopback() {
                                            subnets.push(format!("{}/{}", net, prefix));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("ip").args(["-4", "route", "show"]).output() {
            let s = String::from_utf8_lossy(&output.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[1] == "dev" && !parts[0].starts_with("default") && !parts[0].starts_with("0.0.0.0") {
                    if parts[0].contains("/") && !parts[0].starts_with("127.") && !parts[0].starts_with("100.") {
                        subnets.push(parts[0].to_string());
                    }
                }
            }
        }
    }
    subnets.into_iter().take(3).collect()
}

pub fn set_system_dns(dns_ip: &str) -> Option<DnsGuard> {
    let targets = dns_targets();
    if targets.is_empty() {
        return None;
    }

    let entries: Vec<DnsEntry> = targets
        .into_iter()
        .map(|iface| {
            let servers = dns_capture(&iface);
            DnsEntry { iface, servers }
        })
        .collect();

    persist_dns_state(&entries);

    let tunnel_dns = [dns_ip.to_owned()];
    for entry in &entries {
        let _ = dns_apply(&entry.iface, &tunnel_dns);
    }

    Some(DnsGuard { entries })
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct DnsEntry {
    iface: String,
    servers: Vec<String>,
}

fn dns_state_path() -> Option<std::path::PathBuf> {
    crate::dirs_next().map(|d| d.join(DNS_STATE_FILE))
}

fn persist_dns_state(entries: &[DnsEntry]) {
    let Some(path) = dns_state_path() else { return };
    if let Ok(data) = serde_json::to_vec(entries) {
        let _ = std::fs::write(path, data);
    }
}

fn clear_dns_state() {
    if let Some(path) = dns_state_path() {
        let _ = std::fs::remove_file(path);
    }
}

pub fn restore_orphaned_dns() {
    let Some(path) = dns_state_path() else { return };
    let Ok(data) = std::fs::read(&path) else { return };
    let Ok(entries) = serde_json::from_slice::<Vec<DnsEntry>>(&data) else {
        let _ = std::fs::remove_file(&path);
        return;
    };
    if entries.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let _ = writeln!(
        std::io::stderr(),
        "[vpn-client] restoring DNS left behind by a previous session"
    );
    if restore_dns_entries(&entries) {
        let _ = std::fs::remove_file(&path);
    } else {
        let _ = writeln!(
            std::io::stderr(),
            "[vpn-client] DNS restore incomplete (needs root); rerun with --cleanup"
        );
    }
}

pub fn cleanup_stale_session() {
    restore_orphaned_dns();
    remove_v6_blackhole("");
    cleanup_policy_routing();
}

fn restore_dns_entries(entries: &[DnsEntry]) -> bool {
    let restored = entries
        .iter()
        .all(|entry| dns_apply(&entry.iface, &entry.servers).is_ok());
    dns_flush();
    restored
}

fn parse_dns_servers(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_owned)
        .collect()
}

fn capture_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub struct DnsGuard {
    entries: Vec<DnsEntry>,
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        restore_dns_entries(&self.entries);
        clear_dns_state();
    }
}

#[cfg(target_os = "macos")]
fn dns_targets() -> Vec<String> {
    let Some(text) = capture_cmd("networksetup", &["-listallnetworkservices"]) else {
        return Vec::new();
    };
    text.lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_owned)
        .collect()
}

#[cfg(target_os = "macos")]
fn dns_capture(iface: &str) -> Vec<String> {
    capture_cmd("networksetup", &["-getdnsservers", iface])
        .map(|text| parse_dns_servers(&text))
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn dns_apply(iface: &str, servers: &[String]) -> Result<(), String> {
    let mut args = vec!["-setdnsservers", iface];
    if servers.is_empty() {
        args.push(DNS_MACOS_CLEAR);
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    run_cmd("networksetup", &args)
}

#[cfg(target_os = "macos")]
fn dns_flush() {
    let _ = run_cmd("dscacheutil", &["-flushcache"]);
    let _ = run_cmd("killall", &["-HUP", "mDNSResponder"]);
}

#[cfg(target_os = "linux")]
fn dns_targets() -> Vec<String> {
    detect_active_interface_linux().into_iter().collect()
}

#[cfg(target_os = "linux")]
fn dns_capture(iface: &str) -> Vec<String> {
    capture_cmd("resolvectl", &["dns", iface])
        .map(|text| parse_dns_servers(&text))
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn dns_apply(iface: &str, servers: &[String]) -> Result<(), String> {
    if servers.is_empty() {
        return run_cmd("resolvectl", &["revert", iface]);
    }
    let mut args = vec!["dns", iface];
    args.extend(servers.iter().map(String::as_str));
    run_cmd("resolvectl", &args)
}

#[cfg(target_os = "linux")]
fn dns_flush() {
    let _ = run_cmd("resolvectl", &["flush-caches"]);
}

#[cfg(target_os = "windows")]
fn dns_targets() -> Vec<String> {
    detect_active_interface_windows().into_iter().collect()
}

#[cfg(target_os = "windows")]
fn dns_capture(iface: &str) -> Vec<String> {
    let name_arg = format!("name={}", iface);
    capture_cmd("netsh", &["interface", "ip", "show", "dnsservers", &name_arg])
        .filter(|text| !text.to_lowercase().contains(DNS_WINDOWS_DHCP))
        .map(|text| parse_dns_servers(&text))
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn dns_apply(iface: &str, servers: &[String]) -> Result<(), String> {
    let Some((primary, rest)) = servers.split_first() else {
        return run_cmd("netsh", &["interface", "ip", "set", "dns", iface, DNS_WINDOWS_DHCP]);
    };
    run_cmd("netsh", &["interface", "ip", "set", "dns", iface, "static", primary])?;
    for server in rest {
        let _ = run_cmd("netsh", &["interface", "ip", "add", "dns", iface, server]);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn dns_flush() {
    let _ = run_cmd("ipconfig", &["/flushdns"]);
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn dns_targets() -> Vec<String> {
    Vec::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn dns_capture(_iface: &str) -> Vec<String> {
    Vec::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn dns_apply(_iface: &str, _servers: &[String]) -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn dns_flush() {}

#[cfg(target_os = "linux")]
fn detect_active_interface_linux() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for part in text.split_whitespace() {
        if !part.is_empty() && part != "default" && part != "via" && !part.contains('.') {
            return Some(part.to_string());
        }
    }
    Some("eth0".to_string())
}

#[cfg(target_os = "windows")]
fn detect_active_interface_windows() -> Option<String> {
    let out = std::process::Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.contains("Connected") && (line.contains("Wi-Fi") || line.contains("Ethernet") || line.contains("Local Area")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            return parts.last().map(|s| s.to_string());
        }
    }
    Some("Ethernet".to_string())
}

