#![allow(dead_code)]
#[path = "../src/profiles.rs"]
mod profiles;

use profiles::AppSettings;

const LEGACY_SETTINGS: &str = r#"{
  "connection_mode": "tls",
  "kill_switch": true,
  "dns_leak_protection": false,
  "advertise_routes": "10.0.0.0/8",
  "auto_reconnect": false
}"#;

#[test]
fn settings_written_for_the_retired_server_mode_still_load() {
    let settings: AppSettings = serde_json::from_str(LEGACY_SETTINGS).unwrap();
    assert!(!settings.auto_reconnect);
    assert_eq!(settings.advertise_routes, "10.0.0.0/8");
    assert!(settings.mesh_exit_node.is_empty());
    assert!(!settings.mesh_advertise_exit_node);
    assert!(settings.mesh_network_id.is_empty());
    assert!(settings.project_id.is_empty());
}

#[test]
fn mesh_preferences_round_trip_through_disk_format() {
    let stored = AppSettings {
        mesh_exit_node: "dev_7fb3".to_string(),
        mesh_advertise_exit_node: true,
        mesh_network_id: "net_2a91".to_string(),
        ..AppSettings::default()
    };
    let encoded = serde_json::to_string_pretty(&stored).unwrap();
    let decoded: AppSettings = serde_json::from_str(&encoded).unwrap();
    assert!(decoded == stored);
}

#[test]
fn project_selection_round_trips_through_disk_format() {
    let stored = AppSettings {
        project_id: "prj_41c8".to_string(),
        ..AppSettings::default()
    };
    let decoded: AppSettings = serde_json::from_str(&serde_json::to_string(&stored).unwrap()).unwrap();
    assert_eq!(decoded.project_id, "prj_41c8");
    assert!(decoded == stored);
}

#[test]
fn unchanged_settings_compare_equal_so_no_write_is_needed() {
    let saved = AppSettings::default();
    let mut current = AppSettings::default();
    assert!(current == saved);
    current.mesh_advertise_exit_node = true;
    assert!(current != saved);
    current.mesh_advertise_exit_node = false;
    current.mesh_network_id = "net_2a91".to_string();
    assert!(current != saved);
    current.mesh_network_id.clear();
    current.project_id = "prj_41c8".to_string();
    assert!(current != saved);
}
