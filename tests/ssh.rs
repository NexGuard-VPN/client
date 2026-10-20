#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use nexguard_core::meshnet::{MeshPeerView, PeerPath};
use nexguard_core::meshssh;

fn peer(name: &str, ip: &str) -> MeshPeerView {
    MeshPeerView {
        device_id: format!("dev-{}", name),
        name: name.to_string(),
        ip: ip.to_string(),
        path: PeerPath::Direct,
        rtt_ms: None,
        exit_node: false,
        online: true,
        tx: 0,
        rx: 0,
    }
}

fn from(addr: &str) -> Option<SocketAddr> {
    Some(addr.parse().unwrap())
}

#[test]
fn a_device_in_the_network_is_a_known_caller() {
    let peers = vec![peer("laptop", "100.64.3.3"), peer("server", "100.64.3.5")];
    let caller = meshssh::caller_of(&peers, from("100.64.3.3:51000")).expect("a peer may connect");
    assert_eq!(caller.name, "laptop");
}

#[test]
fn an_address_outside_the_network_is_nobody() {
    let peers = vec![peer("laptop", "100.64.3.3")];
    assert!(meshssh::caller_of(&peers, from("100.64.3.9:51000")).is_none());
    assert!(meshssh::caller_of(&peers, from("192.168.1.10:51000")).is_none());
    assert!(meshssh::caller_of(&peers, from("[fd7a::3]:51000")).is_none());
    assert!(meshssh::caller_of(&peers, None).is_none());
    assert!(meshssh::caller_of(&[], from("100.64.3.3:51000")).is_none());
}

#[test]
fn root_is_never_a_login_account() {
    assert!(meshssh::login_account("root").is_none());
}

#[test]
fn an_unknown_account_is_refused() {
    assert!(meshssh::login_account("no-such-user-nexguard").is_none());
    assert!(meshssh::login_account("bad\0name").is_none());
    assert!(meshssh::login_account("").is_none());
}

#[test]
fn the_current_account_may_log_in_unless_it_is_root() {
    let name = std::env::var("USER").unwrap_or_default();
    let account = meshssh::login_account(&name);
    if unsafe { libc::geteuid() } == 0 || name.is_empty() {
        return;
    }
    let account = account.expect("the account running the tests exists");
    assert_eq!(account.name, name);
    assert_ne!(account.uid, 0);
    assert!(!account.home.is_empty());
    assert!(account.shell.starts_with('/'));
}

#[test]
fn only_locale_and_terminal_variables_pass_through() {
    for name in ["LANG", "LC_ALL", "LC_CTYPE", "TERM"] {
        assert!(meshssh::passes_env(name), "{} should pass", name);
    }
    for name in ["PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "HOME", "SHELL", "lang"] {
        assert!(!meshssh::passes_env(name), "{} must not pass", name);
    }
}

#[test]
fn a_login_shell_is_named_with_a_leading_dash() {
    assert_eq!(meshssh::login_name("/bin/bash"), "-bash");
    assert_eq!(meshssh::login_name("/usr/bin/zsh"), "-zsh");
    assert_eq!(meshssh::login_name("fish"), "-fish");
}

#[test]
fn exit_codes_and_signals_reach_the_client() {
    assert_eq!(meshssh::exit_code(ExitStatus::from_raw(0)), 0);
    assert_eq!(meshssh::exit_code(ExitStatus::from_raw(3 << 8)), 3);
    assert_eq!(meshssh::exit_code(ExitStatus::from_raw(9)), 128 + 9);
}
