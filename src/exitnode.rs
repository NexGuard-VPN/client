#![cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]

use std::ffi::OsStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

pub const UNSUPPORTED_PLATFORM: &str = "exit node mode is not supported on this platform";

const CHAIN_NAT_V4: &str = "NEXGUARD-EXIT-NAT";
const CHAIN_FWD_V4: &str = "NEXGUARD-EXIT-FWD";
const CHAIN_NAT_V6: &str = "NEXGUARD-EXIT-NAT6";
const CHAIN_FWD_V6: &str = "NEXGUARD-EXIT-FWD6";

const IPTABLES_V4: &str = "iptables";
const IPTABLES_V6: &str = "ip6tables";
const TABLE_NAT: &str = "nat";
const HOOK_NAT: &str = "POSTROUTING";
const HOOK_FWD: &str = "FORWARD";
const TARGET_MASQUERADE: &str = "MASQUERADE";
const TARGET_ACCEPT: &str = "ACCEPT";
const TARGET_TCPMSS: &str = "TCPMSS";
const CONNTRACK_STATES: &str = "RELATED,ESTABLISHED";
const TCP_SYN_FLAGS: [&str; 2] = ["SYN,RST", "SYN"];

#[cfg(target_os = "linux")]
const PROC_FORWARD_V4: &str = "/proc/sys/net/ipv4/ip_forward";
#[cfg(target_os = "linux")]
const PROC_FORWARD_V6: &str = "/proc/sys/net/ipv6/conf/all/forwarding";
#[cfg(not(target_os = "linux"))]
const SYSCTL_FORWARD_V4: &str = "net.inet.ip.forwarding";
#[cfg(not(target_os = "linux"))]
const SYSCTL_FORWARD_V6: &str = "net.inet6.ip6.forwarding";
#[cfg(target_os = "macos")]
const SYSCTL_BIN: &str = "sysctl";
const FORWARD_ON: &str = "1";
const FORWARD_OFF: &str = "0";

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const PF_ANCHOR: &str = "com.apple/nexguard-exit";
#[cfg(target_os = "macos")]
const PFCTL_BIN: &str = "pfctl";
#[cfg(target_os = "macos")]
const PF_STDIN: &str = "-";
const PF_TOKEN_LABEL: &str = "Token";
const PF_MAX_MSS: u16 = 1360;

#[cfg(target_os = "linux")]
const IPROUTE_BIN: &str = "ip";
#[cfg(target_os = "macos")]
const NETSTAT_BIN: &str = "netstat";
#[cfg(target_os = "macos")]
const ROUTE_BIN: &str = "route";

const IFACE_NAME_MAX: usize = 15;
const CIDR_SEPARATOR: char = '/';
const PREFIX_MAX_V4: u8 = 32;
const PREFIX_MAX_V6: u8 = 128;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const SUPPORTED: bool = true;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const SUPPORTED: bool = false;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn prefix_max(self) -> u8 {
        match self {
            Family::V4 => PREFIX_MAX_V4,
            Family::V6 => PREFIX_MAX_V6,
        }
    }

    fn pf_keyword(self) -> &'static str {
        match self {
            Family::V4 => "inet",
            Family::V6 => "inet6",
        }
    }

    fn iptables_binary(self) -> &'static str {
        match self {
            Family::V4 => IPTABLES_V4,
            Family::V6 => IPTABLES_V6,
        }
    }

    fn nat_chain(self) -> &'static str {
        match self {
            Family::V4 => CHAIN_NAT_V4,
            Family::V6 => CHAIN_NAT_V6,
        }
    }

    fn fwd_chain(self) -> &'static str {
        match self {
            Family::V4 => CHAIN_FWD_V4,
            Family::V6 => CHAIN_FWD_V6,
        }
    }

    fn forward_key(self) -> &'static str {
        #[cfg(target_os = "linux")]
        match self {
            Family::V4 => PROC_FORWARD_V4,
            Family::V6 => PROC_FORWARD_V6,
        }
        #[cfg(not(target_os = "linux"))]
        match self {
            Family::V4 => SYSCTL_FORWARD_V4,
            Family::V6 => SYSCTL_FORWARD_V6,
        }
    }
}

pub fn parse_cidr(cidr: &str, family: Family) -> Result<String, String> {
    let text = cidr.trim();
    let (addr, prefix) = text
        .split_once(CIDR_SEPARATOR)
        .ok_or_else(|| format!("{} is not a CIDR", text))?;

    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("{} has an invalid prefix length", text))?;
    if prefix > family.prefix_max() {
        return Err(format!("{} has an invalid prefix length", text));
    }

    match family {
        Family::V4 => {
            let addr: Ipv4Addr = addr
                .parse()
                .map_err(|_| format!("{} is not an IPv4 network", text))?;
            let mask = shift_mask(u32::MAX, u32::from(prefix), u32::BITS);
            Ok(format!("{}{}{}", Ipv4Addr::from(u32::from(addr) & mask), CIDR_SEPARATOR, prefix))
        }
        Family::V6 => {
            let addr: Ipv6Addr = addr
                .parse()
                .map_err(|_| format!("{} is not an IPv6 network", text))?;
            let mask = shift_mask(u128::MAX, u32::from(prefix), u128::BITS);
            Ok(format!("{}{}{}", Ipv6Addr::from(u128::from(addr) & mask), CIDR_SEPARATOR, prefix))
        }
    }
}

fn shift_mask<T>(all_ones: T, prefix: u32, bits: u32) -> T
where
    T: std::ops::Shl<u32, Output = T> + Default,
{
    if prefix == 0 {
        T::default()
    } else {
        all_ones << (bits - prefix)
    }
}

pub fn validate_iface(name: &str) -> Result<String, String> {
    let valid = !name.is_empty()
        && name.len() <= IFACE_NAME_MAX
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'));

    if valid {
        Ok(name.to_owned())
    } else {
        Err(format!("{:?} is not a valid interface name", name))
    }
}

pub struct ExitPlan {
    pub iface: String,
    pub tun: String,
    pub v4: String,
    pub v6: Option<String>,
}

impl ExitPlan {
    pub fn new(
        tun_name: &str,
        mesh_cidr: &str,
        mesh_cidr_v6: Option<&str>,
        iface: &str,
    ) -> Result<Self, String> {
        let iface = validate_iface(iface)?;
        let tun = validate_iface(tun_name)?;
        if tun == iface {
            return Err(format!("{} cannot be both tunnel and uplink", tun));
        }
        Ok(Self {
            iface,
            tun,
            v4: parse_cidr(mesh_cidr, Family::V4)?,
            v6: mesh_cidr_v6
                .map(|c| parse_cidr(c, Family::V6))
                .transpose()?,
        })
    }

    fn families(&self) -> Vec<(Family, &str)> {
        let mut out = vec![(Family::V4, self.v4.as_str())];
        if let Some(v6) = self.v6.as_deref() {
            out.push((Family::V6, v6));
        }
        out
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn iptables_plan(&self) -> Vec<Vec<String>> {
        self.families()
            .into_iter()
            .flat_map(|(family, cidr)| self.iptables_family_plan(family, cidr))
            .collect()
    }

    fn iptables_family_plan(&self, family: Family, cidr: &str) -> Vec<Vec<String>> {
        let bin = family.iptables_binary();
        let nat = family.nat_chain();
        let fwd = family.fwd_chain();
        let clamp = |input: &str, output: &str| {
            argv(bin, &[
                "-A", fwd, "-i", input, "-o", output,
                "-p", "tcp", "--tcp-flags", TCP_SYN_FLAGS[0], TCP_SYN_FLAGS[1],
                "-j", TARGET_TCPMSS, "--clamp-mss-to-pmtu",
            ])
        };

        vec![
            argv(bin, &["-t", TABLE_NAT, "-N", nat]),
            argv(bin, &["-t", TABLE_NAT, "-A", HOOK_NAT, "-j", nat]),
            argv(bin, &[
                "-t", TABLE_NAT, "-A", nat,
                "-s", cidr, "-o", &self.iface, "-j", TARGET_MASQUERADE,
            ]),
            argv(bin, &["-N", fwd]),
            argv(bin, &["-A", HOOK_FWD, "-j", fwd]),
            clamp(&self.tun, &self.iface),
            clamp(&self.iface, &self.tun),
            argv(bin, &[
                "-A", fwd, "-i", &self.tun, "-o", &self.iface,
                "-s", cidr, "-j", TARGET_ACCEPT,
            ]),
            argv(bin, &[
                "-A", fwd, "-i", &self.iface, "-o", &self.tun, "-d", cidr,
                "-m", "conntrack", "--ctstate", CONNTRACK_STATES, "-j", TARGET_ACCEPT,
            ]),
        ]
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn pf_ruleset(&self) -> String {
        let mut lines = vec![format!("scrub on {} all max-mss {}", self.tun, PF_MAX_MSS)];
        let mut filters = Vec::new();

        for (family, cidr) in self.families() {
            let keyword = family.pf_keyword();
            lines.push(format!(
                "nat on {iface} {keyword} from {cidr} to any -> ({iface})",
                iface = self.iface
            ));
            filters.push(format!(
                "pass in on {} {} from {} to any keep state",
                self.tun, keyword, cidr
            ));
            filters.push(format!(
                "pass out on {iface} {keyword} from ({iface}) to any keep state",
                iface = self.iface
            ));
        }

        lines.extend(filters);
        lines.push(String::new());
        lines.join("\n")
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn iptables_teardown() -> Vec<Vec<String>> {
    [Family::V4, Family::V6]
        .into_iter()
        .flat_map(|family| {
            let bin = family.iptables_binary();
            let nat = family.nat_chain();
            let fwd = family.fwd_chain();
            [
                argv(bin, &["-t", TABLE_NAT, "-D", HOOK_NAT, "-j", nat]),
                argv(bin, &["-t", TABLE_NAT, "-F", nat]),
                argv(bin, &["-t", TABLE_NAT, "-X", nat]),
                argv(bin, &["-D", HOOK_FWD, "-j", fwd]),
                argv(bin, &["-F", fwd]),
                argv(bin, &["-X", fwd]),
            ]
        })
        .collect()
}

fn argv(binary: &str, args: &[&str]) -> Vec<String> {
    std::iter::once(binary.to_owned())
        .chain(args.iter().map(|a| (*a).to_owned()))
        .collect()
}

struct Forwarding {
    key: &'static str,
    previous: Option<String>,
}

impl Forwarding {
    fn enable(family: Family) -> Self {
        let key = family.forward_key();
        let previous = read_forward(key)
            .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or_else(|| FORWARD_OFF.to_owned());
        write_forward(key, FORWARD_ON);
        Self { key, previous: Some(previous) }
    }

    fn restore(&mut self) {
        if let Some(previous) = self.previous.take() {
            write_forward(self.key, &previous);
        }
    }
}

#[cfg(target_os = "linux")]
fn read_forward(key: &str) -> Option<String> {
    std::fs::read_to_string(key).ok().map(|v| v.trim().to_owned())
}

#[cfg(target_os = "linux")]
fn write_forward(key: &str, value: &str) {
    let _ = std::fs::write(key, value);
}

#[cfg(target_os = "macos")]
fn read_forward(key: &str) -> Option<String> {
    capture(SYSCTL_BIN, &["-n", key]).map(|v| v.trim().to_owned())
}

#[cfg(target_os = "macos")]
fn write_forward(key: &str, value: &str) {
    run_ignore(SYSCTL_BIN, &["-w".to_owned(), format!("{}={}", key, value)]);
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_forward(_key: &str) -> Option<String> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn write_forward(_key: &str, _value: &str) {}

struct Firewall {
    #[cfg(target_os = "macos")]
    token: Option<String>,
}

#[cfg(target_os = "linux")]
impl Firewall {
    fn purge() {
        for cmd in iptables_teardown() {
            run_ignore(&cmd[0], &cmd[1..]);
        }
    }

    fn install(plan: &ExitPlan) -> Result<Self, String> {
        for cmd in plan.iptables_plan() {
            run(&cmd[0], &cmd[1..])?;
        }
        Ok(Self {})
    }

    fn remove(&mut self) {
        Self::purge();
    }
}

#[cfg(target_os = "macos")]
impl Firewall {
    fn purge() {
        pf_flush_anchor(PF_ANCHOR);
    }

    fn install(plan: &ExitPlan) -> Result<Self, String> {
        Ok(Self {
            token: pf_load_anchor(PF_ANCHOR, &plan.pf_ruleset())?,
        })
    }

    fn remove(&mut self) {
        pf_unload_anchor(PF_ANCHOR, self.token.take());
    }
}

#[cfg(target_os = "macos")]
pub fn pf_flush_anchor(anchor: &str) {
    run_ignore(
        PFCTL_BIN,
        &["-a".to_owned(), anchor.to_owned(), "-F".to_owned(), "all".to_owned()],
    );
}

#[cfg(target_os = "macos")]
pub fn pf_load_anchor(anchor: &str, ruleset: &str) -> Result<Option<String>, String> {
    feed(PFCTL_BIN, &["-a", anchor, "-f", PF_STDIN], ruleset)?;
    Ok(capture(PFCTL_BIN, &["-E"]).and_then(|out| parse_pf_token(&out)))
}

#[cfg(target_os = "macos")]
pub fn pf_unload_anchor(anchor: &str, token: Option<String>) {
    pf_flush_anchor(anchor);
    if let Some(token) = token {
        run_ignore(PFCTL_BIN, &["-X".to_owned(), token]);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Firewall {
    fn purge() {}

    fn install(_plan: &ExitPlan) -> Result<Self, String> {
        Err(UNSUPPORTED_PLATFORM.to_owned())
    }

    fn remove(&mut self) {}
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_pf_token(output: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.trim_start().starts_with(PF_TOKEN_LABEL))
        .and_then(|l| l.rsplit(char::is_whitespace).next())
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()))
        .map(str::to_owned)
}

pub struct ExitNodeState {
    forwarding: Vec<Forwarding>,
    firewall: Firewall,
    active: bool,
}

impl ExitNodeState {
    pub fn is_supported() -> bool {
        SUPPORTED
    }

    pub fn activate(
        tun_name: &str,
        mesh_cidr: &str,
        mesh_cidr_v6: Option<&str>,
    ) -> Result<Self, String> {
        if !Self::is_supported() {
            return Err(UNSUPPORTED_PLATFORM.to_owned());
        }

        let iface = uplink_iface(tun_name)?;
        let plan = ExitPlan::new(tun_name, mesh_cidr, mesh_cidr_v6, &iface)?;

        Firewall::purge();

        let mut forwarding = vec![Forwarding::enable(Family::V4)];
        if plan.v6.is_some() {
            forwarding.push(Forwarding::enable(Family::V6));
        }

        match Firewall::install(&plan) {
            Ok(firewall) => Ok(Self { forwarding, firewall, active: true }),
            Err(e) => {
                Firewall::purge();
                forwarding.iter_mut().for_each(Forwarding::restore);
                Err(e)
            }
        }
    }

    pub fn cleanup(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        self.firewall.remove();
        self.forwarding.iter_mut().for_each(Forwarding::restore);
    }
}

impl Drop for ExitNodeState {
    fn drop(&mut self) {
        self.cleanup()
    }
}

#[cfg(target_os = "linux")]
fn uplink_iface(tun_name: &str) -> Result<String, String> {
    let text = capture(IPROUTE_BIN, &["route", "show", "default"])
        .ok_or_else(|| "could not read the default route".to_owned())?;

    let mut fallback = None;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let field = |name: &str| {
            parts
                .iter()
                .position(|p| *p == name)
                .and_then(|i| parts.get(i + 1))
                .copied()
        };
        let dev = match field("dev") {
            Some(dev) if dev != tun_name => dev,
            _ => continue,
        };
        if field("via").is_some() {
            return validate_iface(dev);
        }
        fallback.get_or_insert(dev);
    }

    fallback
        .ok_or_else(|| "no physical uplink interface found".to_owned())
        .and_then(validate_iface)
}

#[cfg(target_os = "macos")]
fn uplink_iface(tun_name: &str) -> Result<String, String> {
    let text = capture(NETSTAT_BIN, &["-rn", "-f", "inet"])
        .ok_or_else(|| "could not read the routing table".to_owned())?;

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 || parts[0] != "default" || parts[3] == tun_name {
            continue;
        }
        if parts[1].parse::<Ipv4Addr>().is_ok() {
            return validate_iface(parts[3]);
        }
    }

    capture(ROUTE_BIN, &["-n", "get", "default"])
        .and_then(|out| {
            out.lines()
                .filter_map(|l| l.trim().strip_prefix("interface:"))
                .map(|v| v.trim().to_owned())
                .find(|iface| iface != tun_name)
        })
        .ok_or_else(|| "no physical uplink interface found".to_owned())
        .and_then(|iface| validate_iface(&iface))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn uplink_iface(_tun_name: &str) -> Result<String, String> {
    Err(UNSUPPORTED_PLATFORM.to_owned())
}

fn describe<S: AsRef<OsStr>>(binary: &str, args: &[S]) -> String {
    std::iter::once(binary.to_owned())
        .chain(args.iter().map(|a| a.as_ref().to_string_lossy().into_owned()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "linux")]
fn run<S: AsRef<OsStr>>(binary: &str, args: &[S]) -> Result<(), String> {
    let output = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("{}: {}", describe(binary, args), e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} failed: {}",
            describe(binary, args),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_ignore<S: AsRef<OsStr>>(binary: &str, args: &[S]) {
    let _ = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn capture<S: AsRef<OsStr>>(binary: &str, args: &[S]) -> Option<String> {
    let output = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Some(text)
}

#[cfg(target_os = "macos")]
fn feed<S: AsRef<OsStr>>(binary: &str, args: &[S], input: &str) -> Result<(), String> {
    use std::io::Write;

    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {}", describe(binary, args), e))?;

    child
        .stdin
        .take()
        .ok_or_else(|| format!("{}: stdin unavailable", describe(binary, args)))?
        .write_all(input.as_bytes())
        .map_err(|e| format!("{}: {}", describe(binary, args), e))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("{}: {}", describe(binary, args), e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} failed: {}",
            describe(binary, args),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}
