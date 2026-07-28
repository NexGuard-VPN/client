use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::Mutex;

static ACTIVE_TUNS: Mutex<Vec<String>> = Mutex::new(Vec::new());

const RELAY_PORT: u16 = 443;
const CONTROL_PORT: u16 = 9190;
const SESSION_MARKER: &str = "active-session";
const DNS_STATE_MARKER: &str = "dns-previous";
const DNS_NO_SERVERS: &str = "no usable DNS servers provided";
const V6_HALF_LOW: &str = "::/1";
const V6_HALF_HIGH: &str = "8000::/1";
const V6_PROBE_ADDR: &str = "2606:4700:4700::1111";

pub fn register_active_tun(name: &str) {
    if let Ok(mut g) = ACTIVE_TUNS.lock() {
        if !g.iter().any(|n| n == name) {
            g.push(name.to_string());
        }
    }
    mark_active_session(name);
}

pub fn unregister_active_tun(name: &str) {
    if let Ok(mut g) = ACTIVE_TUNS.lock() {
        g.retain(|n| n != name);
    }
}

pub fn cleanup_active_tuns() {
    let names: Vec<String> = ACTIVE_TUNS.try_lock().map(|g| g.clone()).unwrap_or_default();
    for n in names {
        emergency_cleanup(&n);
    }
    deactivate_kill_switch();
    restore_orphaned_dns();
    clear_active_session();
}

fn state_marker_path(marker: &str) -> Option<std::path::PathBuf> {
    crate::dirs_next().map(|d| d.join(marker))
}

fn store_state(marker: &str, value: &str) {
    if let Some(path) = state_marker_path(marker) {
        let _ = std::fs::write(&path, value);
    }
}

fn load_state(marker: &str) -> Option<String> {
    let path = state_marker_path(marker)?;
    let value = std::fs::read_to_string(&path).ok()?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn clear_state(marker: &str) {
    if let Some(path) = state_marker_path(marker) {
        let _ = std::fs::remove_file(&path);
    }
}

fn mark_active_session(name: &str) {
    store_state(SESSION_MARKER, name);
}

pub fn clear_active_session() {
    clear_state(SESSION_MARKER);
}

pub fn cleanup_orphaned() {
    if let Some(tun) = load_state(SESSION_MARKER) {
        emergency_cleanup(&tun);
        clear_state(SESSION_MARKER);
    }
    restore_orphaned_dns();
    deactivate_kill_switch();
}

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

        let mut state = Self {
            preserved_ips: preserved,
            original_gateway: gw,
            original_iface: iface,
            tun_name: tun_name.to_owned(),
            has_v6: enable_v6,
            v6_blackhole: false,
        };

        add_default_via_tun(tun_name)?;

        if enable_v6 {
            if let Err(e) = add_default_v6_via_tun(tun_name) {
                let _ = writeln!(std::io::stderr(), "[vpn-client] ipv6 tunnel route incomplete: {}", e);
            }
        } else {
            state.v6_blackhole = true;
            if let Err(e) = add_v6_blackhole(tun_name) {
                let _ = writeln!(std::io::stderr(), "[vpn-client] ipv6 blackhole incomplete: {}", e);
            }
        }

        verify_v6(tun_name, enable_v6)?;

        Ok(state)
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
const V6_ROUTE_METRIC: &str = "1";
#[cfg(target_os = "linux")]
const V6_LOOPBACK_IFACE: &str = "lo";
#[cfg(target_os = "linux")]
const V6_BLACKHOLE_KEYWORD: &str = "blackhole";

#[cfg(target_os = "macos")]
const V6_BLACKHOLE_GATEWAY: &str = "::1";
#[cfg(target_os = "macos")]
const V6_LOOPBACK_IFACE: &str = "lo0";
#[cfg(target_os = "macos")]
const V6_BLACKHOLE_FLAG: &str = "BLACKHOLE";

#[cfg(target_os = "windows")]
const V6_ANY: &str = "::/0";
#[cfg(target_os = "windows")]
const V6_METRIC_ARG: &str = "metric=1";
#[cfg(target_os = "windows")]
const WIN_STORE_ACTIVE: &str = "store=active";
#[cfg(target_os = "windows")]
const WIN_LOOPBACK_NAME: &str = "Loopback";
#[cfg(target_os = "windows")]
const WIN_LOOPBACK_INDEX: &str = "1";
#[cfg(target_os = "windows")]
const V6_FW_RULE_SUFFIX: &str = "V6Block";

#[cfg(target_os = "linux")]
fn add_default_v6_via_tun(tun: &str) -> Result<(), String> {
    let low = run_cmd("ip", &["-6", "route", "add", V6_HALF_LOW, "dev", tun]);
    let high = run_cmd("ip", &["-6", "route", "add", V6_HALF_HIGH, "dev", tun]);
    low.and(high)
}

#[cfg(target_os = "macos")]
fn add_default_v6_via_tun(tun: &str) -> Result<(), String> {
    let low = run_cmd("route", &["-n", "add", "-inet6", V6_HALF_LOW, "-interface", tun]);
    let high = run_cmd("route", &["-n", "add", "-inet6", V6_HALF_HIGH, "-interface", tun]);
    low.and(high)
}

#[cfg(target_os = "windows")]
fn add_default_v6_via_tun(tun: &str) -> Result<(), String> {
    let idx = get_interface_index(tun).unwrap_or_default();
    v6_add_routes(&idx)
}

#[cfg(target_os = "windows")]
fn v6_add_routes(idx: &str) -> Result<(), String> {
    let iface = format!("interface={}", idx);
    let low = run_cmd("netsh", &["interface", "ipv6", "add", "route", V6_HALF_LOW, &iface, V6_METRIC_ARG, WIN_STORE_ACTIVE]);
    let high = run_cmd("netsh", &["interface", "ipv6", "add", "route", V6_HALF_HIGH, &iface, V6_METRIC_ARG, WIN_STORE_ACTIVE]);
    low.and(high)
}

#[cfg(target_os = "windows")]
fn v6_delete_routes(idx: &str) {
    let iface = format!("interface={}", idx);
    let _ = run_cmd("netsh", &["interface", "ipv6", "delete", "route", V6_HALF_LOW, &iface]);
    let _ = run_cmd("netsh", &["interface", "ipv6", "delete", "route", V6_HALF_HIGH, &iface]);
}

#[cfg(target_os = "linux")]
fn remove_default_v6_via_tun(tun: &str) {
    let _ = run_cmd("ip", &["-6", "route", "del", V6_HALF_LOW, "dev", tun]);
    let _ = run_cmd("ip", &["-6", "route", "del", V6_HALF_HIGH, "dev", tun]);
}

#[cfg(target_os = "macos")]
fn remove_default_v6_via_tun(_tun: &str) {
    let _ = run_cmd("route", &["-n", "delete", "-inet6", V6_HALF_LOW]);
    let _ = run_cmd("route", &["-n", "delete", "-inet6", V6_HALF_HIGH]);
}

#[cfg(target_os = "windows")]
fn remove_default_v6_via_tun(tun: &str) {
    v6_delete_routes(&get_interface_index(tun).unwrap_or_default());
}

#[cfg(target_os = "linux")]
fn add_v6_blackhole(_tun: &str) -> Result<(), String> {
    let low = run_cmd("ip", &["-6", "route", "add", "blackhole", V6_HALF_LOW, "metric", V6_ROUTE_METRIC]);
    let high = run_cmd("ip", &["-6", "route", "add", "blackhole", V6_HALF_HIGH, "metric", V6_ROUTE_METRIC]);
    low.and(high)
}

#[cfg(target_os = "macos")]
fn add_v6_blackhole(_tun: &str) -> Result<(), String> {
    let mut result = Ok(());
    for prefix in [V6_HALF_LOW, V6_HALF_HIGH] {
        let attempt = run_cmd("route", &["-n", "add", "-inet6", "-blackhole", prefix, V6_BLACKHOLE_GATEWAY])
            .or_else(|_| run_cmd("route", &["-n", "add", "-inet6", prefix, V6_BLACKHOLE_GATEWAY]))
            .or_else(|_| run_cmd("route", &["-n", "add", "-inet6", prefix, "-interface", V6_LOOPBACK_IFACE]));
        if let Err(e) = attempt {
            if result.is_ok() {
                result = Err(e);
            }
        }
    }
    result
}

#[cfg(target_os = "windows")]
fn add_v6_blackhole(_tun: &str) -> Result<(), String> {
    let routes = v6_add_routes(&v6_loopback_index());
    let name = format!("name={}", v6_fw_rule_name());
    let remote = format!("remoteip={}", V6_ANY);
    let block = run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule", &name,
        "dir=out", "action=block", "profile=any", "enable=yes", &remote,
    ]);
    routes.and(block)
}

#[cfg(target_os = "windows")]
fn v6_fw_rule_name() -> String {
    format!("{}-{}", FW_RULE_PREFIX, V6_FW_RULE_SUFFIX)
}

#[cfg(target_os = "windows")]
fn v6_loopback_index() -> String {
    capture_ok("netsh", &["interface", "ipv6", "show", "interfaces"])
        .and_then(|text| {
            text.lines()
                .find(|l| l.contains(WIN_LOOPBACK_NAME))
                .and_then(|l| l.split_whitespace().next().map(|s| s.to_owned()))
        })
        .unwrap_or_else(|| WIN_LOOPBACK_INDEX.to_owned())
}

#[cfg(target_os = "linux")]
fn remove_v6_blackhole(_tun: &str) {
    let _ = run_cmd("ip", &["-6", "route", "del", "blackhole", V6_HALF_LOW]);
    let _ = run_cmd("ip", &["-6", "route", "del", "blackhole", V6_HALF_HIGH]);
}

#[cfg(target_os = "macos")]
fn remove_v6_blackhole(_tun: &str) {
    let _ = run_cmd("route", &["-n", "delete", "-inet6", V6_HALF_LOW]);
    let _ = run_cmd("route", &["-n", "delete", "-inet6", V6_HALF_HIGH]);
}

#[cfg(target_os = "windows")]
fn remove_v6_blackhole(_tun: &str) {
    v6_delete_routes(&v6_loopback_index());
    let name = format!("name={}", v6_fw_rule_name());
    let _ = run_cmd("netsh", &["advfirewall", "firewall", "delete", "rule", &name]);
}

fn verify_v6(tun: &str, tunnel: bool) -> Result<(), String> {
    match v6_egress_iface()? {
        None => {
            if tunnel {
                let _ = writeln!(
                    std::io::stderr(),
                    "[vpn-client] ipv6 has no route to {}, tunnel v6 inactive",
                    V6_PROBE_ADDR
                );
            }
            Ok(())
        }
        Some(dev) => {
            let ok = v6_iface_matches_tun(&dev, tun) || (!tunnel && v6_iface_is_blackhole(&dev));
            if ok {
                Ok(())
            } else {
                Err(format!("ipv6 leak: {} routes via {}", V6_PROBE_ADDR, dev))
            }
        }
    }
}

#[cfg(unix)]
fn v6_iface_matches_tun(dev: &str, tun: &str) -> bool {
    dev == tun
}

#[cfg(unix)]
fn v6_iface_is_blackhole(dev: &str) -> bool {
    dev == V6_LOOPBACK_IFACE
}

#[cfg(target_os = "windows")]
fn v6_iface_matches_tun(dev: &str, tun: &str) -> bool {
    get_interface_index(tun).map(|idx| idx == dev).unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn v6_iface_is_blackhole(dev: &str) -> bool {
    dev == v6_loopback_index()
}

#[cfg(target_os = "linux")]
fn v6_egress_iface() -> Result<Option<String>, String> {
    let out = capture_cmd("ip", &["-6", "route", "get", V6_PROBE_ADDR])?;
    if !out.success {
        return Ok(None);
    }
    let lower = out.text.to_lowercase();
    if lower.contains(V6_BLACKHOLE_KEYWORD) {
        return Ok(None);
    }
    let parts: Vec<&str> = out.text.split_whitespace().collect();
    for i in 0..parts.len() {
        if parts[i] == "dev" && i + 1 < parts.len() {
            return Ok(Some(parts[i + 1].to_owned()));
        }
    }
    Err("ip -6 route get: no device in reply".into())
}

#[cfg(target_os = "macos")]
fn v6_egress_iface() -> Result<Option<String>, String> {
    let out = capture_cmd("route", &["-n", "get", "-inet6", V6_PROBE_ADDR])?;
    if !out.success {
        return Ok(None);
    }
    let mut iface = None;
    for line in out.text.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("interface:") {
            iface = Some(val.trim().to_owned());
        }
        if let Some(val) = trimmed.strip_prefix("flags:") {
            if val.contains(V6_BLACKHOLE_FLAG) {
                return Ok(None);
            }
        }
    }
    iface.map(Some).ok_or_else(|| "route get -inet6: no interface in reply".to_owned())
}

#[cfg(target_os = "windows")]
fn v6_egress_iface() -> Result<Option<String>, String> {
    match find_net_route_index() {
        Ok(dev) => Ok(dev),
        Err(_) => v6_half_route_owner(),
    }
}

#[cfg(target_os = "windows")]
fn find_net_route_index() -> Result<Option<String>, String> {
    let script = format!(
        "(Find-NetRoute -RemoteIPAddress '{}' -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceIndex",
        V6_PROBE_ADDR
    );
    let out = capture_cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])?;
    if !out.success {
        return Err(format!("Find-NetRoute: {}", out.text.trim()));
    }
    let idx = out.text.trim().to_owned();
    if idx.is_empty() {
        Ok(None)
    } else {
        Ok(Some(idx))
    }
}

#[cfg(target_os = "windows")]
fn v6_half_route_owner() -> Result<Option<String>, String> {
    let text = capture_ok("netsh", &["interface", "ipv6", "show", "route"])
        .ok_or_else(|| "netsh ipv6 show route failed".to_owned())?;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|p| *p == V6_HALF_LOW) {
            if let Some(idx) = parts.get(pos + 1) {
                return Ok(Some((*idx).to_owned()));
            }
        }
    }
    Ok(None)
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

#[cfg(unix)]
const RUNTIME_DIR: &str = "/var/run/nexguard";
#[cfg(unix)]
const RUNTIME_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const RUNTIME_FILE_MODE: u32 = 0o600;

#[cfg(unix)]
fn runtime_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(RUNTIME_DIR).join(name)
}

#[cfg(unix)]
fn ensure_runtime_dir() -> Result<(), String> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    DirBuilder::new()
        .recursive(true)
        .mode(RUNTIME_DIR_MODE)
        .create(RUNTIME_DIR)
        .map_err(|e| format!("create {}: {}", RUNTIME_DIR, e))?;
    std::fs::set_permissions(RUNTIME_DIR, Permissions::from_mode(RUNTIME_DIR_MODE))
        .map_err(|e| format!("chmod {}: {}", RUNTIME_DIR, e))
}

#[cfg(unix)]
fn write_private_file(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    ensure_runtime_dir()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(RUNTIME_FILE_MODE)
        .open(path)
        .map_err(|e| format!("open {}: {}", path.display(), e))?;
    file.write_all(data)
        .map_err(|e| format!("write {}: {}", path.display(), e))
}

#[cfg(target_os = "macos")]
const PF_RULES_NAME: &str = "kill-switch.pf.conf";
#[cfg(target_os = "macos")]
const PF_ANCHOR: &str = "com.apple/nexguard";
#[cfg(target_os = "macos")]
const PF_STATE_MARKER: &str = "pf-was-enabled";
#[cfg(target_os = "macos")]
const PF_STATE_ENABLED: &str = "enabled";
#[cfg(target_os = "macos")]
const PF_STATE_DISABLED: &str = "disabled";

#[cfg(target_os = "macos")]
static PF_WAS_ENABLED: Mutex<Option<bool>> = Mutex::new(None);

#[cfg(target_os = "macos")]
fn pf_is_enabled() -> Option<bool> {
    let out = std::process::Command::new("pfctl")
        .args(["-s", "info"])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let status = text.lines().next()?.trim().strip_prefix("Status:")?.trim();
    Some(status.starts_with("Enabled"))
}

#[cfg(target_os = "macos")]
fn pf_build_rules(tun_name: &str, server_ips: &[&str]) -> String {
    let mut rules = String::new();
    rules.push_str("pass quick on lo0 all\n");
    rules.push_str(&format!("pass quick on {} all\n", tun_name));
    for ip in server_ips {
        rules.push_str(&format!("pass out quick proto tcp to {} port {}\n", ip, RELAY_PORT));
        rules.push_str(&format!("pass out quick proto tcp to {} port {}\n", ip, CONTROL_PORT));
    }
    rules.push_str("block drop out quick all\n");
    rules
}

#[cfg(target_os = "macos")]
fn pf_rules_path() -> std::path::PathBuf {
    runtime_path(PF_RULES_NAME)
}

#[cfg(target_os = "macos")]
fn pf_write_rules(rules: &str) -> Result<(), String> {
    write_private_file(&pf_rules_path(), rules.as_bytes())
}

#[cfg(target_os = "macos")]
fn pf_remember(was_enabled: bool) {
    if let Ok(mut guard) = PF_WAS_ENABLED.lock() {
        *guard = Some(was_enabled);
    }
    store_state(
        PF_STATE_MARKER,
        if was_enabled { PF_STATE_ENABLED } else { PF_STATE_DISABLED },
    );
}

#[cfg(target_os = "macos")]
fn pf_recall() -> Option<bool> {
    let remembered = PF_WAS_ENABLED.lock().ok().and_then(|mut guard| guard.take());
    let persisted = load_state(PF_STATE_MARKER).map(|v| v == PF_STATE_ENABLED);
    clear_state(PF_STATE_MARKER);
    remembered.or(persisted)
}

#[cfg(target_os = "macos")]
fn activate_kill_switch(tun_name: &str, server_ips: &[&str]) -> Result<(), String> {
    let was_enabled = pf_is_enabled().unwrap_or(false);
    pf_write_rules(&pf_build_rules(tun_name, server_ips))?;
    let rules_path = pf_rules_path();
    run_cmd("pfctl", &["-a", PF_ANCHOR, "-f", &rules_path.to_string_lossy()])
        .map_err(|e| format!("pfctl anchor load: {}", e))?;
    if !was_enabled {
        run_cmd("pfctl", &["-e"]).map_err(|e| format!("pfctl enable: {}", e))?;
    }
    pf_remember(was_enabled);
    Ok(())
}

#[cfg(target_os = "macos")]
fn deactivate_kill_switch() {
    let _ = run_cmd("pfctl", &["-a", PF_ANCHOR, "-F", "all"]);
    let _ = std::fs::remove_file(pf_rules_path());
    if pf_recall() == Some(false) {
        let _ = run_cmd("pfctl", &["-d"]);
    }
}

#[cfg(target_os = "linux")]
fn activate_kill_switch(tun_name: &str, server_ips: &[&str]) -> Result<(), String> {
    let relay_port = RELAY_PORT.to_string();
    let control_port = CONTROL_PORT.to_string();

    run_cmd("iptables", &["-N", "NEXGUARD-KS"]).ok();
    run_cmd("iptables", &["-F", "NEXGUARD-KS"])?;
    run_cmd("iptables", &["-A", "NEXGUARD-KS", "-o", tun_name, "-j", "ACCEPT"])?;
    run_cmd("iptables", &["-A", "NEXGUARD-KS", "-o", "lo", "-j", "ACCEPT"])?;
    run_cmd("iptables", &["-A", "NEXGUARD-KS", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
    for ip in server_ips {
        run_cmd("iptables", &["-A", "NEXGUARD-KS", "-d", ip, "-p", "tcp", "--dport", &relay_port, "-j", "ACCEPT"])?;
        run_cmd("iptables", &["-A", "NEXGUARD-KS", "-d", ip, "-p", "tcp", "--dport", &control_port, "-j", "ACCEPT"])?;
    }
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
const FW_RULE_PREFIX: &str = "NexGuard";
#[cfg(target_os = "windows")]
const FW_RULE_SUFFIX: &str = "KillSwitch";
#[cfg(target_os = "windows")]
const FW_PROFILE: &str = "currentprofile";
#[cfg(target_os = "windows")]
const FW_DEFAULT_POLICY: &str = "blockinbound,allowoutbound";
#[cfg(target_os = "windows")]
const FW_BLOCK_OUTBOUND: &str = "blockoutbound";
#[cfg(target_os = "windows")]
const FW_LOOPBACK_V4: &str = "127.0.0.0/8";
#[cfg(target_os = "windows")]
const FW_LOOPBACK_V6: &str = "::1/128";
#[cfg(target_os = "windows")]
const FW_POLICY_MARKER: &str = "fw-previous-policy";

#[cfg(target_os = "windows")]
static FW_PREV_POLICY: Mutex<Option<String>> = Mutex::new(None);

#[cfg(target_os = "windows")]
fn fw_rule_name() -> String {
    format!("{}-{}", FW_RULE_PREFIX, FW_RULE_SUFFIX)
}

#[cfg(target_os = "windows")]
fn fw_current_policy() -> Option<String> {
    let out = std::process::Command::new("netsh")
        .args(["advfirewall", "show", FW_PROFILE, "firewallpolicy"])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let lowered = line.trim().to_lowercase();
        if !lowered.starts_with("firewall policy") {
            continue;
        }
        let policy = lowered.split_whitespace().last()?.to_owned();
        let (inbound, outbound) = policy.split_once(',')?;
        if inbound.ends_with("inbound") && outbound.ends_with("outbound") {
            return Some(policy);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn fw_blocking_policy(previous: &str) -> String {
    let inbound = previous.split(',').next().unwrap_or("blockinbound");
    format!("{},{}", inbound, FW_BLOCK_OUTBOUND)
}

#[cfg(target_os = "windows")]
fn fw_set_policy(policy: &str) -> Result<(), String> {
    run_cmd("netsh", &["advfirewall", "set", FW_PROFILE, "firewallpolicy", policy])
}

#[cfg(target_os = "windows")]
fn fw_add_allow_rule(scope: &[&str]) -> Result<(), String> {
    let name = format!("name={}", fw_rule_name());
    let mut args: Vec<&str> = vec!["advfirewall", "firewall", "add", "rule", name.as_str(), "dir=out", "action=allow", "profile=any", "enable=yes"];
    args.extend_from_slice(scope);
    run_cmd("netsh", &args)
}

#[cfg(target_os = "windows")]
fn tun_ipv4_address(tun_name: &str) -> Option<String> {
    let out = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "addresses", &format!("name={}", tun_name)])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("IP Address:") {
            let ip = rest.trim();
            if !ip.is_empty() {
                return Some(ip.to_owned());
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn fw_apply(tun_name: &str, server_ips: &[&str]) -> Result<(), String> {
    let tun_ip = tun_ipv4_address(tun_name)
        .ok_or_else(|| format!("no ipv4 address on {}", tun_name))?;
    let previous = fw_current_policy().unwrap_or_else(|| FW_DEFAULT_POLICY.to_owned());
    let relay_port = format!("remoteport={}", RELAY_PORT);
    let control_port = format!("remoteport={}", CONTROL_PORT);

    fw_add_allow_rule(&[&format!("localip={}", tun_ip)])?;
    fw_add_allow_rule(&[&format!("remoteip={}", FW_LOOPBACK_V4)])?;
    fw_add_allow_rule(&[&format!("remoteip={}", FW_LOOPBACK_V6)])?;
    for ip in server_ips {
        let remote = format!("remoteip={}", ip);
        fw_add_allow_rule(&["protocol=tcp", &remote, &relay_port])?;
        fw_add_allow_rule(&["protocol=tcp", &remote, &control_port])?;
    }

    fw_set_policy(&fw_blocking_policy(&previous))?;
    if let Ok(mut guard) = FW_PREV_POLICY.lock() {
        *guard = Some(previous.clone());
    }
    store_state(FW_POLICY_MARKER, &previous);
    Ok(())
}

#[cfg(target_os = "windows")]
fn activate_kill_switch(tun_name: &str, server_ips: &[&str]) -> Result<(), String> {
    match fw_apply(tun_name, server_ips) {
        Ok(()) => Ok(()),
        Err(e) => {
            deactivate_kill_switch();
            Err(e)
        }
    }
}

#[cfg(target_os = "windows")]
fn deactivate_kill_switch() {
    let name = format!("name={}", fw_rule_name());
    let _ = run_cmd("netsh", &["advfirewall", "firewall", "delete", "rule", &name]);

    let remembered = FW_PREV_POLICY.lock().ok().and_then(|mut guard| guard.take());
    let previous = remembered.or_else(|| load_state(FW_POLICY_MARKER));
    clear_state(FW_POLICY_MARKER);
    if let Some(policy) = previous {
        let _ = fw_set_policy(&policy);
    }
}

struct CmdOutput {
    success: bool,
    text: String,
}

fn capture_cmd(cmd: &str, args: &[&str]) -> Result<CmdOutput, String> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{} {}: {}", cmd, args.join(" "), e))?;

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(CmdOutput { success: output.status.success(), text })
}

fn capture_ok(cmd: &str, args: &[&str]) -> Option<String> {
    capture_cmd(cmd, args).ok().filter(|o| o.success).map(|o| o.text)
}

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

pub struct DnsState {
    snapshot: DnsSnapshot,
}

impl DnsState {
    pub fn apply(tun_name: &str, servers: &[String]) -> Result<Self, String> {
        let servers = sanitize_servers(servers);
        if servers.is_empty() {
            return Err(DNS_NO_SERVERS.into());
        }

        let snapshot = dns_capture(tun_name)?;
        if let Ok(encoded) = serde_json::to_string(&snapshot) {
            store_state(DNS_STATE_MARKER, &encoded);
        }

        match dns_push(tun_name, &servers, &snapshot) {
            Ok(()) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "[vpn-client] dns routed through {} ({})",
                    tun_name,
                    servers.join(" ")
                );
                Ok(Self { snapshot })
            }
            Err(e) => {
                dns_restore(&snapshot);
                clear_state(DNS_STATE_MARKER);
                Err(e)
            }
        }
    }
}

impl Drop for DnsState {
    fn drop(&mut self) {
        dns_restore(&self.snapshot);
        clear_state(DNS_STATE_MARKER);
        let _ = writeln!(std::io::stderr(), "[vpn-client] dns restored");
    }
}

pub fn restore_orphaned_dns() {
    let Some(encoded) = load_state(DNS_STATE_MARKER) else {
        return;
    };
    if let Ok(snapshot) = serde_json::from_str::<DnsSnapshot>(&encoded) {
        let _ = writeln!(std::io::stderr(), "[vpn-client] restoring orphaned dns configuration");
        dns_restore(&snapshot);
    }
    clear_state(DNS_STATE_MARKER);
}

fn sanitize_servers(servers: &[String]) -> Vec<String> {
    servers
        .iter()
        .map(|s| s.trim())
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
        .map(|s| s.to_owned())
        .collect()
}

#[cfg(target_os = "macos")]
const NS_EMPTY_TOKEN: &str = "empty";
#[cfg(target_os = "macos")]
const NS_NONE_MARKER: &str = "aren't any";
#[cfg(target_os = "macos")]
const NS_DISABLED_PREFIX: char = '*';

#[cfg(target_os = "macos")]
#[derive(Serialize, Deserialize)]
struct DnsServiceEntry {
    service: String,
    servers: Vec<String>,
}

#[cfg(target_os = "macos")]
#[derive(Serialize, Deserialize)]
struct DnsSnapshot {
    services: Vec<DnsServiceEntry>,
}

#[cfg(target_os = "macos")]
fn network_services() -> Vec<String> {
    let Some(text) = capture_ok("networksetup", &["-listallnetworkservices"]) else {
        return Vec::new();
    };
    text.lines()
        .skip(1)
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with(NS_DISABLED_PREFIX))
        .map(|l| l.to_owned())
        .collect()
}

#[cfg(target_os = "macos")]
fn dns_capture(_tun: &str) -> Result<DnsSnapshot, String> {
    let names = network_services();
    if names.is_empty() {
        return Err("no enabled network services".into());
    }
    let services = names
        .into_iter()
        .map(|service| {
            let text = capture_ok("networksetup", &["-getdnsservers", &service]).unwrap_or_default();
            let servers = if text.contains(NS_NONE_MARKER) {
                Vec::new()
            } else {
                sanitize_servers(&text.lines().map(|l| l.to_owned()).collect::<Vec<String>>())
            };
            DnsServiceEntry { service, servers }
        })
        .collect();
    Ok(DnsSnapshot { services })
}

#[cfg(target_os = "macos")]
fn dns_push(_tun: &str, servers: &[String], snapshot: &DnsSnapshot) -> Result<(), String> {
    for entry in &snapshot.services {
        let mut args: Vec<&str> = vec!["-setdnsservers", entry.service.as_str()];
        args.extend(servers.iter().map(|s| s.as_str()));
        run_cmd("networksetup", &args)?;
    }
    dns_flush();
    Ok(())
}

#[cfg(target_os = "macos")]
fn dns_restore(snapshot: &DnsSnapshot) {
    for entry in &snapshot.services {
        let mut args: Vec<&str> = vec!["-setdnsservers", entry.service.as_str()];
        if entry.servers.is_empty() {
            args.push(NS_EMPTY_TOKEN);
        } else {
            args.extend(entry.servers.iter().map(|s| s.as_str()));
        }
        let _ = run_cmd("networksetup", &args);
    }
    dns_flush();
}

#[cfg(target_os = "macos")]
fn dns_flush() {
    let _ = run_cmd("dscacheutil", &["-flushcache"]);
    let _ = run_cmd("killall", &["-HUP", "mDNSResponder"]);
}

#[cfg(target_os = "linux")]
const RESOLV_CONF: &str = "/etc/resolv.conf";
#[cfg(target_os = "linux")]
const RESOLV_CONF_MODE: u32 = 0o644;
#[cfg(target_os = "linux")]
const RESOLV_BACKUP_NAME: &str = "resolv.conf.bak";
#[cfg(target_os = "linux")]
const RESOLVED_RUNTIME_DIR: &str = "/run/systemd/resolve";
#[cfg(target_os = "linux")]
const RESOLVED_BIN: &str = "resolvectl";
#[cfg(target_os = "linux")]
const RESOLVED_ROUTE_DOMAIN: &str = "~.";

#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
enum DnsSnapshot {
    Resolved { tun: String },
    ResolvConf { backup: String, link_target: Option<String> },
}

#[cfg(target_os = "linux")]
fn resolved_available() -> bool {
    std::path::Path::new(RESOLVED_RUNTIME_DIR).exists()
        && capture_ok(RESOLVED_BIN, &["--version"]).is_some()
}

#[cfg(target_os = "linux")]
fn dns_capture(tun: &str) -> Result<DnsSnapshot, String> {
    if resolved_available() {
        return Ok(DnsSnapshot::Resolved { tun: tun.to_owned() });
    }
    let path = std::path::Path::new(RESOLV_CONF);
    let link_target = std::fs::read_link(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let content = std::fs::read(path).unwrap_or_default();
    let backup = runtime_path(RESOLV_BACKUP_NAME);
    write_private_file(&backup, &content)?;
    Ok(DnsSnapshot::ResolvConf {
        backup: backup.to_string_lossy().into_owned(),
        link_target,
    })
}

#[cfg(target_os = "linux")]
fn dns_push(tun: &str, servers: &[String], snapshot: &DnsSnapshot) -> Result<(), String> {
    match snapshot {
        DnsSnapshot::Resolved { .. } => {
            let mut args: Vec<&str> = vec!["dns", tun];
            args.extend(servers.iter().map(|s| s.as_str()));
            run_cmd(RESOLVED_BIN, &args)?;
            run_cmd(RESOLVED_BIN, &["domain", tun, RESOLVED_ROUTE_DOMAIN])?;
            let _ = run_cmd(RESOLVED_BIN, &["flush-caches"]);
            Ok(())
        }
        DnsSnapshot::ResolvConf { .. } => {
            let content: String = servers
                .iter()
                .map(|s| format!("nameserver {}\n", s))
                .collect();
            write_resolv_conf(content.as_bytes())
        }
    }
}

#[cfg(target_os = "linux")]
fn dns_restore(snapshot: &DnsSnapshot) {
    match snapshot {
        DnsSnapshot::Resolved { tun } => {
            let _ = run_cmd(RESOLVED_BIN, &["revert", tun]);
            let _ = run_cmd(RESOLVED_BIN, &["flush-caches"]);
        }
        DnsSnapshot::ResolvConf { backup, link_target } => {
            let path = std::path::Path::new(RESOLV_CONF);
            if let Some(target) = link_target {
                let _ = std::fs::remove_file(path);
                let _ = std::os::unix::fs::symlink(target, path);
            } else if let Ok(data) = std::fs::read(backup) {
                let _ = write_resolv_conf(&data);
            }
            let _ = std::fs::remove_file(backup);
        }
    }
}

#[cfg(target_os = "linux")]
fn write_resolv_conf(data: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let path = std::path::Path::new(RESOLV_CONF);
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        std::fs::remove_file(path).map_err(|e| format!("remove {}: {}", RESOLV_CONF, e))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(RESOLV_CONF_MODE)
        .open(path)
        .map_err(|e| format!("open {}: {}", RESOLV_CONF, e))?;
    file.write_all(data)
        .map_err(|e| format!("write {}: {}", RESOLV_CONF, e))
}

#[cfg(target_os = "windows")]
const WIN_FAMILY_V4: &str = "ipv4";
#[cfg(target_os = "windows")]
const WIN_FAMILY_V6: &str = "ipv6";
#[cfg(target_os = "windows")]
const WIN_DNS_HEADER_PREFIX: &str = "Configuration for interface";
#[cfg(target_os = "windows")]
const WIN_DNS_DHCP_MARKER: &str = "DHCP";
#[cfg(target_os = "windows")]
const WIN_DNS_SOURCE_DHCP: &str = "dhcp";
#[cfg(target_os = "windows")]
const WIN_DNS_SOURCE_STATIC: &str = "static";
#[cfg(target_os = "windows")]
const WIN_DNS_NONE: &str = "none";
#[cfg(target_os = "windows")]
const WIN_DNS_REGISTER: &str = "primary";
#[cfg(target_os = "windows")]
const WIN_DNS_NO_VALIDATE: &str = "validate=no";

#[cfg(target_os = "windows")]
#[derive(Serialize, Deserialize)]
struct DnsAdapterEntry {
    name: String,
    dhcp: bool,
    servers: Vec<String>,
}

#[cfg(target_os = "windows")]
#[derive(Serialize, Deserialize)]
struct DnsSnapshot {
    v4: Vec<DnsAdapterEntry>,
    v6: Vec<DnsAdapterEntry>,
}

#[cfg(target_os = "windows")]
fn dns_capture(_tun: &str) -> Result<DnsSnapshot, String> {
    let v4 = dns_capture_family(WIN_FAMILY_V4);
    let v6 = dns_capture_family(WIN_FAMILY_V6);
    if v4.is_empty() && v6.is_empty() {
        return Err("could not enumerate dns adapters".into());
    }
    Ok(DnsSnapshot { v4, v6 })
}

#[cfg(target_os = "windows")]
fn dns_capture_family(family: &str) -> Vec<DnsAdapterEntry> {
    let Some(text) = capture_ok("netsh", &["interface", family, "show", "dnsservers"]) else {
        return Vec::new();
    };
    let mut entries: Vec<DnsAdapterEntry> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = interface_header_name(trimmed) {
            entries.push(DnsAdapterEntry { name, dhcp: false, servers: Vec::new() });
            continue;
        }
        let Some(entry) = entries.last_mut() else {
            continue;
        };
        if trimmed.contains(WIN_DNS_DHCP_MARKER) {
            entry.dhcp = true;
        }
        if let Some(ip) = trailing_ip(trimmed) {
            entry.servers.push(ip);
        }
    }
    entries
}

#[cfg(target_os = "windows")]
fn interface_header_name(line: &str) -> Option<String> {
    let rest = line.strip_prefix(WIN_DNS_HEADER_PREFIX)?;
    Some(rest.trim().trim_matches('"').to_owned())
}

#[cfg(target_os = "windows")]
fn trailing_ip(line: &str) -> Option<String> {
    let token = line.split_whitespace().last()?;
    token.parse::<std::net::IpAddr>().ok().map(|_| token.to_owned())
}

#[cfg(target_os = "windows")]
fn split_families(servers: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for server in servers {
        match server.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => v4.push(server.clone()),
            Ok(std::net::IpAddr::V6(_)) => v6.push(server.clone()),
            Err(_) => {}
        }
    }
    (v4, v6)
}

#[cfg(target_os = "windows")]
fn dns_push(tun: &str, servers: &[String], snapshot: &DnsSnapshot) -> Result<(), String> {
    let (v4, v6) = split_families(servers);
    dns_push_family(WIN_FAMILY_V4, tun, &v4, &snapshot.v4)?;
    dns_push_family(WIN_FAMILY_V6, tun, &v6, &snapshot.v6)?;
    let _ = run_cmd("ipconfig", &["/flushdns"]);
    Ok(())
}

#[cfg(target_os = "windows")]
fn dns_push_family(
    family: &str,
    tun: &str,
    servers: &[String],
    entries: &[DnsAdapterEntry],
) -> Result<(), String> {
    if !servers.is_empty() {
        set_dns_static(family, tun, servers)?;
    }
    for entry in entries {
        if entry.name == tun || (entry.servers.is_empty() && !entry.dhcp) {
            continue;
        }
        let _ = if servers.is_empty() {
            set_dns_none(family, &entry.name)
        } else {
            set_dns_static(family, &entry.name, servers)
        };
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_dns_static(family: &str, name: &str, servers: &[String]) -> Result<(), String> {
    let name_arg = format!("name={}", name);
    let primary = servers.first().ok_or_else(|| DNS_NO_SERVERS.to_owned())?;
    run_cmd("netsh", &[
        "interface", family, "set", "dnsservers", &name_arg,
        WIN_DNS_SOURCE_STATIC, primary, WIN_DNS_REGISTER, WIN_DNS_NO_VALIDATE,
    ])?;
    for (position, server) in servers.iter().enumerate().skip(1) {
        let index = format!("index={}", position + 1);
        run_cmd("netsh", &[
            "interface", family, "add", "dnsservers", &name_arg,
            server, &index, WIN_DNS_NO_VALIDATE,
        ])?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_dns_none(family: &str, name: &str) -> Result<(), String> {
    let name_arg = format!("name={}", name);
    run_cmd("netsh", &[
        "interface", family, "set", "dnsservers", &name_arg,
        WIN_DNS_SOURCE_STATIC, WIN_DNS_NONE,
    ])
}

#[cfg(target_os = "windows")]
fn dns_restore(snapshot: &DnsSnapshot) {
    dns_restore_family(WIN_FAMILY_V4, &snapshot.v4);
    dns_restore_family(WIN_FAMILY_V6, &snapshot.v6);
    let _ = run_cmd("ipconfig", &["/flushdns"]);
}

#[cfg(target_os = "windows")]
fn dns_restore_family(family: &str, entries: &[DnsAdapterEntry]) {
    for entry in entries {
        if entry.dhcp {
            let name_arg = format!("name={}", entry.name);
            let _ = run_cmd("netsh", &[
                "interface", family, "set", "dnsservers", &name_arg, WIN_DNS_SOURCE_DHCP,
            ]);
        } else if entry.servers.is_empty() {
            let _ = set_dns_none(family, &entry.name);
        } else {
            let _ = set_dns_static(family, &entry.name, &entry.servers);
        }
    }
}

