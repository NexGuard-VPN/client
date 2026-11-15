#[path = "../src/desktop.rs"]
mod desktop;

use std::collections::HashMap;

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |key| map.get(key).cloned()
}

#[test]
fn a_server_without_any_display_is_headless() {
    assert!(!desktop::has_display(env(&[])));
}

#[test]
fn an_x11_session_has_a_display() {
    assert!(desktop::has_display(env(&[("DISPLAY", ":0")])));
}

#[test]
fn a_wayland_session_has_a_display() {
    assert!(desktop::has_display(env(&[("WAYLAND_DISPLAY", "wayland-0")])));
}

#[test]
fn an_empty_display_variable_counts_as_none() {
    assert!(!desktop::has_display(env(&[("DISPLAY", ""), ("WAYLAND_DISPLAY", "  ")])));
}

#[test]
fn the_linux_desktop_build_updates_from_its_own_artifact() {
    assert_eq!(desktop::update_platform("linux", "amd64", true), "linux-desktop-amd64");
    assert_eq!(desktop::update_platform("linux", "arm64", true), "linux-desktop-arm64");
}

#[test]
fn the_linux_cli_build_keeps_the_server_artifact() {
    assert_eq!(desktop::update_platform("linux", "amd64", false), "linux-amd64");
}

#[test]
fn macos_and_windows_keys_do_not_change_with_the_interface() {
    assert_eq!(desktop::update_platform("macos", "arm64", true), "macos-arm64");
    assert_eq!(desktop::update_platform("windows", "amd64", true), "windows-amd64");
}
