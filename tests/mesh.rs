#![allow(dead_code)]
#[path = "../src/allowed.rs"]
mod allowed;
#[path = "../src/derpframe.rs"]
mod derpframe;
#[path = "../src/disco.rs"]
mod disco;
#[path = "../src/rng.rs"]
mod rng;
#[path = "../src/stun.rs"]
mod stun;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

const SECRET: &[u8] = b"disco-secret-for-tests-0123456789";
const OTHER_SECRET: &[u8] = b"a-completely-different-secret-xyz";

fn key(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn v4(dotted: &str) -> u32 {
    u32::from(dotted.parse::<Ipv4Addr>().unwrap())
}

fn pick<'a>(table: &'a [(&'a str, Vec<allowed::Cidr>)], dst: u32) -> Option<&'a str> {
    table
        .iter()
        .filter_map(|(name, cidrs)| allowed::best_prefix(cidrs, dst).map(|p| (*name, p)))
        .max_by_key(|&(_, prefix)| prefix)
        .map(|(name, _)| name)
}

#[test]
fn parses_cidr_and_masks_host_bits() {
    assert_eq!(allowed::parse("10.1.2.3/24"), Some((v4("10.1.2.0"), 0xffffff00, 24)));
    assert_eq!(allowed::parse("0.0.0.0/0"), Some((0, 0, 0)));
    assert_eq!(allowed::parse("10.0.0.1/32"), Some((v4("10.0.0.1"), u32::MAX, 32)));
}

#[test]
fn rejects_malformed_cidr() {
    assert_eq!(allowed::parse("10.0.0.1"), None);
    assert_eq!(allowed::parse("10.0.0.1/33"), None);
    assert_eq!(allowed::parse("not-an-ip/24"), None);
    assert_eq!(allowed::parse(""), None);
}

#[test]
fn longest_prefix_wins() {
    let table = vec![allowed::parse("10.0.0.0/8").unwrap(), allowed::parse("10.1.0.0/16").unwrap()];
    assert_eq!(allowed::best_prefix(&table, v4("10.1.2.3")), Some(16));
    assert_eq!(allowed::best_prefix(&table, v4("10.2.2.3")), Some(8));
    assert_eq!(allowed::best_prefix(&table, v4("11.0.0.1")), None);
}

#[test]
fn exit_node_does_not_capture_peer_traffic() {
    let peer = vec![allowed::host("100.64.0.3".parse().unwrap())];
    let exit = vec![
        allowed::host("100.64.0.4".parse().unwrap()),
        allowed::DEFAULT_ROUTE,
    ];
    let table = vec![("peer", peer), ("exit", exit)];

    assert_eq!(pick(&table, v4("100.64.0.3")), Some("peer"));
    assert_eq!(pick(&table, v4("100.64.0.4")), Some("exit"));
    assert_eq!(pick(&table, v4("8.8.8.8")), Some("exit"));
}

#[test]
fn without_an_exit_node_internet_traffic_is_unrouted() {
    let table = vec![("peer", vec![allowed::host("100.64.0.3".parse().unwrap())])];
    assert_eq!(pick(&table, v4("8.8.8.8")), None);
}

#[test]
fn advertised_subnet_routes_are_matched() {
    let table = vec![(
        "gateway",
        vec![
            allowed::host("100.64.0.5".parse().unwrap()),
            allowed::parse("192.168.50.0/24").unwrap(),
        ],
    )];
    assert_eq!(pick(&table, v4("192.168.50.20")), Some("gateway"));
    assert_eq!(pick(&table, v4("192.168.51.20")), None);
}

#[test]
fn disco_ping_round_trips() {
    let sender = key(7);
    let frame = disco::encode(SECRET, disco::PING, &sender, 42, &[1, 2, 3, 4, 5, 6, 7, 8], None);
    let decoded = disco::decode(SECRET, &frame).expect("ping decodes");
    assert_eq!(decoded.kind, disco::PING);
    assert_eq!(decoded.sender, sender);
    assert_eq!(decoded.counter, 42);
    assert_eq!(decoded.tx_id, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(decoded.observed.is_none());
}

#[test]
fn disco_pong_carries_the_observed_address() {
    let observed: SocketAddr = "203.0.113.9:41641".parse().unwrap();
    let frame = disco::encode(SECRET, disco::PONG, &key(1), 9, &[9; 8], Some(observed));
    let decoded = disco::decode(SECRET, &frame).expect("pong decodes");
    assert_eq!(decoded.kind, disco::PONG);
    assert_eq!(decoded.observed, Some(observed));
}

#[test]
fn disco_pong_carries_ipv6_observed_address() {
    let observed: SocketAddr = "[2001:db8::1]:41641".parse().unwrap();
    let frame = disco::encode(SECRET, disco::PONG, &key(2), 10, &[3; 8], Some(observed));
    let decoded = disco::decode(SECRET, &frame).expect("pong decodes");
    assert_eq!(decoded.observed, Some(observed));
}

#[test]
fn disco_rejects_a_foreign_secret() {
    let frame = disco::encode(SECRET, disco::PING, &key(3), 1, &[0; 8], None);
    assert!(disco::decode(OTHER_SECRET, &frame).is_none());
}

#[test]
fn disco_rejects_tampering() {
    let frame = disco::encode(SECRET, disco::PING, &key(4), 1, &[0; 8], None);

    let mut flipped_counter = frame.clone();
    flipped_counter[44] ^= 0x01;
    assert!(disco::decode(SECRET, &flipped_counter).is_none());

    let mut flipped_payload = frame.clone();
    let last = flipped_payload.len() - 1;
    flipped_payload[last] ^= 0x01;
    assert!(disco::decode(SECRET, &flipped_payload).is_none());

    let mut flipped_sender = frame;
    flipped_sender[10] ^= 0x01;
    assert!(disco::decode(SECRET, &flipped_sender).is_none());
}

#[test]
fn disco_rejects_short_and_foreign_datagrams() {
    assert!(!disco::is_disco(b"short"));
    assert!(!disco::is_disco(&[0u8; 128]));
    let wireguard_handshake = [1u8, 0, 0, 0, 5, 6, 7, 8];
    assert!(!disco::is_disco(&wireguard_handshake));
    assert!(disco::decode(SECRET, &wireguard_handshake).is_none());
}

#[test]
fn disco_frame_is_recognisable() {
    let frame = disco::encode(SECRET, disco::PING, &key(5), 1, &[0; 8], None);
    assert!(disco::is_disco(&frame));
}

#[test]
fn derp_relay_frame_round_trips() {
    let dst = key(11);
    let mut buf = Vec::new();
    derpframe::encode_relay(&mut buf, &dst, b"payload");

    let (frame, size) = derpframe::next_frame(&buf).unwrap().unwrap();
    assert_eq!(size, buf.len());
    assert_eq!(frame.kind, derpframe::FRAME_RELAY);
    let (parsed_key, data) = derpframe::split_addressed(frame.payload).unwrap();
    assert_eq!(parsed_key, dst);
    assert_eq!(data, b"payload");
}

#[test]
fn derp_decodes_back_to_back_frames() {
    let mut buf = Vec::new();
    derpframe::encode_relay(&mut buf, &key(1), b"one");
    derpframe::encode_keepalive(&mut buf);
    derpframe::encode_relay(&mut buf, &key(2), b"two");

    let mut kinds = Vec::new();
    let mut consumed = 0;
    while let Ok(Some((frame, size))) = derpframe::next_frame(&buf[consumed..]) {
        kinds.push(frame.kind);
        consumed += size;
    }
    assert_eq!(consumed, buf.len());
    assert_eq!(
        kinds,
        vec![
            derpframe::FRAME_RELAY,
            derpframe::FRAME_KEEPALIVE,
            derpframe::FRAME_RELAY
        ]
    );
}

#[test]
fn derp_waits_for_the_rest_of_a_partial_frame() {
    let mut buf = Vec::new();
    derpframe::encode_relay(&mut buf, &key(1), b"incomplete");
    let truncated = &buf[..buf.len() - 3];
    assert!(matches!(derpframe::next_frame(truncated), Ok(None)));
    assert!(matches!(derpframe::next_frame(&buf[..2]), Ok(None)));
}

#[test]
fn derp_rejects_an_oversized_frame() {
    let mut buf = vec![derpframe::FRAME_RELAY];
    buf.extend_from_slice(&((derpframe::MAX_FRAME + 1) as u32).to_be_bytes());
    assert!(derpframe::next_frame(&buf).is_err());
}

#[test]
fn derp_keepalive_has_no_payload() {
    let mut buf = Vec::new();
    derpframe::encode_keepalive(&mut buf);
    let (frame, size) = derpframe::next_frame(&buf).unwrap().unwrap();
    assert_eq!(size, derpframe::HEADER_LEN);
    assert!(frame.payload.is_empty());
    assert!(derpframe::split_addressed(frame.payload).is_none());
}

#[test]
fn derp_rejects_an_addressed_frame_with_no_body() {
    let payload = [0u8; derpframe::KEY_LEN];
    assert!(derpframe::split_addressed(&payload).is_none());
}

#[test]
fn stun_recognises_only_binding_responses() {
    let mut response = vec![0x01, 0x01, 0x00, 0x00];
    response.extend_from_slice(&0x2112A442u32.to_be_bytes());
    response.extend_from_slice(&[0u8; 12]);
    assert!(stun::is_binding_response(&response));

    let mut wrong_cookie = response.clone();
    wrong_cookie[4] = 0x00;
    assert!(!stun::is_binding_response(&wrong_cookie));

    let mut request = response.clone();
    request[1] = 0x00;
    assert!(!stun::is_binding_response(&request));

    assert!(!stun::is_binding_response(&[0u8; 8]));
}

#[test]
fn stun_probe_parses_its_own_reflexive_address() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().unwrap();

    let probe = stun::Probe::send(&client, server_addr).expect("request sent");

    let mut request = [0u8; 64];
    let (n, from) = server.recv_from(&mut request).unwrap();
    assert_eq!(n, 20);
    let txn = &request[8..20];

    let mapped: SocketAddr = "198.51.100.7:51820".parse().unwrap();
    let response = binding_response(txn, mapped);
    server.send_to(&response, from).unwrap();

    let mut buf = [0u8; 128];
    let (n, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(probe.parse(&buf[..n]), Some(mapped));
}

#[test]
fn stun_probe_ignores_a_foreign_transaction() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let probe = stun::Probe::send(&client, server.local_addr().unwrap()).unwrap();

    let mapped: SocketAddr = "198.51.100.8:1234".parse().unwrap();
    let response = binding_response(&[0xAA; 12], mapped);
    assert_eq!(probe.parse(&response), None);
}

#[test]
fn stun_servers_are_configurable() {
    let defaults = stun::servers();
    assert!(!defaults.is_empty());
    assert!(defaults.iter().all(|s| s.contains(':')));
}

fn binding_response(txn: &[u8], mapped: SocketAddr) -> Vec<u8> {
    const MAGIC_COOKIE: u32 = 0x2112A442;
    let ip = match mapped.ip() {
        std::net::IpAddr::V4(v4) => u32::from(v4),
        _ => unreachable!(),
    };
    let mut attr = Vec::new();
    attr.extend_from_slice(&0x0020u16.to_be_bytes());
    attr.extend_from_slice(&8u16.to_be_bytes());
    attr.push(0);
    attr.push(0x01);
    attr.extend_from_slice(&(mapped.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    attr.extend_from_slice(&(ip ^ MAGIC_COOKIE).to_be_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(&0x0101u16.to_be_bytes());
    out.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(txn);
    out.extend_from_slice(&attr);
    out
}

#[test]
fn rng_fills_every_byte_requested() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rng::fill(&mut a);
    rng::fill(&mut b);
    assert_ne!(a, b);
    assert!(a.iter().any(|&x| x != 0));
}

#[test]
fn rng_index_stays_in_range() {
    for bound in [1usize, 2, 14, 150] {
        for _ in 0..64 {
            assert!(rng::index(bound) < bound);
        }
    }
}

#[path = "../src/meshtypes.rs"]
mod meshtypes;

const NETMAP_SAMPLE: &str = r#"{
  "version": 42,
  "self": {"device_id":"d-1","name":"macbook","mesh_ip":"100.64.3.2","routes":["192.168.1.0/24"],"exit_node":false},
  "network": {"id":"n-1","cidr":"100.64.3.0/24","dns_suffix":"alice.mesh","disco_secret":"c2VjcmV0"},
  "relays": ["tunnel.nexguard.sh:443"],
  "peers": [{"device_id":"d-2","name":"homepc","public_key":"cGsx","mesh_ip":"100.64.3.3",
             "endpoints":["93.184.2.1:41641","192.168.1.7:41641"],
             "exit_node":true,"routes":["10.0.0.0/24"],"online":true,"last_seen":1757568000}]
}"#;

const ENROLL_SAMPLE: &str = r#"{
  "device_id":"d-1","token":"jwt-here","mesh_ip":"100.64.3.2",
  "network":{"id":"n-1","cidr":"100.64.3.0/24","dns_suffix":"alice.mesh","disco_secret":"c2VjcmV0"},
  "relays":["tunnel.nexguard.sh:443"]
}"#;

#[test]
fn netmap_contract_deserializes() {
    let map: meshtypes::NetMap = serde_json::from_str(NETMAP_SAMPLE).expect("netmap parses");
    assert_eq!(map.version, 42);
    assert_eq!(map.device.mesh_ip, "100.64.3.2");
    assert_eq!(map.device.name, "macbook");
    assert_eq!(map.network.cidr, "100.64.3.0/24");
    assert_eq!(map.network.disco_secret, "c2VjcmV0");
    assert_eq!(map.relays, vec!["tunnel.nexguard.sh:443"]);
    assert_eq!(map.peers.len(), 1);
    let peer = &map.peers[0];
    assert_eq!(peer.device_id, "d-2");
    assert_eq!(peer.public_key, "cGsx");
    assert_eq!(peer.endpoints.len(), 2);
    assert!(peer.exit_node);
    assert!(peer.online);
    assert_eq!(peer.routes, vec!["10.0.0.0/24"]);
}

#[test]
fn netmap_tolerates_missing_optional_fields() {
    let map: meshtypes::NetMap =
        serde_json::from_str(r#"{"version":1,"peers":[]}"#).expect("sparse netmap parses");
    assert_eq!(map.version, 1);
    assert!(map.peers.is_empty());
    assert!(map.device.mesh_ip.is_empty());
    assert!(map.relays.is_empty());
}

#[test]
fn enroll_contract_deserializes() {
    let id: meshtypes::MeshIdentity = serde_json::from_str(ENROLL_SAMPLE).expect("enroll parses");
    assert_eq!(id.device_id, "d-1");
    assert_eq!(id.token, "jwt-here");
    assert_eq!(id.mesh_ip, "100.64.3.2");
    assert_eq!(id.network.dns_suffix, "alice.mesh");
    assert_eq!(id.relays, vec!["tunnel.nexguard.sh:443"]);
    assert!(id.public_key.is_empty());
}

#[test]
fn identity_round_trips_through_disk_format() {
    let mut id: meshtypes::MeshIdentity = serde_json::from_str(ENROLL_SAMPLE).unwrap();
    id.public_key = "cHVibGlj".to_string();
    let encoded = serde_json::to_string(&id).unwrap();
    let decoded: meshtypes::MeshIdentity = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.public_key, "cHVibGlj");
    assert_eq!(decoded.network.cidr, "100.64.3.0/24");
}

#[test]
fn device_patch_omits_untouched_fields() {
    let patch = meshtypes::DevicePatch { exit_node: Some(true), ..Default::default() };
    assert_eq!(serde_json::to_string(&patch).unwrap(), r#"{"exit_node":true}"#);

    let empty = meshtypes::DevicePatch::default();
    assert_eq!(serde_json::to_string(&empty).unwrap(), "{}");
}

#[path = "../src/cli.rs"]
mod cli;

fn argv(args: &[&str]) -> Vec<String> {
    std::iter::once("nexguard")
        .chain(args.iter().copied())
        .map(String::from)
        .collect()
}

#[test]
fn join_token_is_read_from_the_bare_command_and_the_flag() {
    assert_eq!(cli::join_token(&argv(&["join", "ngj_abc"])), Some("ngj_abc".into()));
    assert_eq!(
        cli::join_token(&argv(&["--join-token", "ngj_abc", "--mesh"])),
        Some("ngj_abc".into())
    );
    assert_eq!(
        cli::join_token(&argv(&["join", "ngj_abc", "--share-internet"])),
        Some("ngj_abc".into())
    );
}

#[test]
fn join_token_is_absent_without_one() {
    assert_eq!(cli::join_token(&argv(&["--mesh"])), None);
    assert_eq!(cli::join_token(&argv(&["join"])), None);
    assert_eq!(cli::join_token(&argv(&["join", "--share-internet"])), None);
    assert_eq!(cli::join_token(&argv(&["--join-token"])), None);
    assert_eq!(cli::join_token(&argv(&["--login", "join", "ngj_abc"])), None);
}

#[test]
fn enroll_request_carries_the_join_token_only_when_joining() {
    let base = meshtypes::EnrollRequest {
        network_id: None,
        project_id: None,
        join_token: None,
        name: "web-01".into(),
        public_key: "key".into(),
        os: "linux".into(),
        os_version: "ubuntu 24.04".into(),
        client_version: "1.16.0".into(),
        advertise_exit_node: true,
        advertise_routes: vec![],
    };
    let without = serde_json::to_string(&base).unwrap();
    assert!(!without.contains("join_token"), "absent token must not be sent: {}", without);

    let with = serde_json::to_string(&meshtypes::EnrollRequest {
        join_token: Some("ngj_abc".into()),
        ..base
    })
    .unwrap();
    assert!(with.contains("\"join_token\":\"ngj_abc\""), "token must be sent: {}", with);
}

#[path = "../src/path.rs"]
mod path;

mod path_choice {
    use super::path::{choose, PathSample};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    const FRESH: Duration = Duration::from_secs(20);

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn measured(a: &str, lan: bool, rtt_ms: u64, age: Duration, now: Instant) -> PathSample {
        PathSample {
            addr: addr(a),
            lan,
            rtt: Some(Duration::from_millis(rtt_ms)),
            last_pong: Some(now - age),
            last_data: None,
        }
    }

    fn claimed(a: &str) -> PathSample {
        PathSample { addr: addr(a), lan: false, rtt: None, last_pong: None, last_data: None }
    }

    fn carrying(a: &str, age: Duration, now: Instant) -> PathSample {
        PathSample {
            addr: addr(a),
            lan: false,
            rtt: None,
            last_pong: None,
            last_data: Some(now - age),
        }
    }

    #[test]
    fn a_measured_path_beats_one_that_is_only_claimed() {
        let now = Instant::now();
        let samples = [claimed("1.1.1.1:1111"), measured("2.2.2.2:2222", false, 30, Duration::ZERO, now)];
        assert_eq!(choose(&samples, now, FRESH), Some(addr("2.2.2.2:2222")));
    }

    #[test]
    fn the_lan_wins_even_when_it_is_slower() {
        let now = Instant::now();
        let samples = [
            measured("9.9.9.9:9999", false, 5, Duration::ZERO, now),
            measured("192.168.1.7:7777", true, 40, Duration::ZERO, now),
        ];
        assert_eq!(choose(&samples, now, FRESH), Some(addr("192.168.1.7:7777")));
    }

    #[test]
    fn the_lower_round_trip_wins_among_equals() {
        let now = Instant::now();
        let samples = [
            measured("1.1.1.1:1111", false, 80, Duration::ZERO, now),
            measured("2.2.2.2:2222", false, 20, Duration::ZERO, now),
        ];
        assert_eq!(choose(&samples, now, FRESH), Some(addr("2.2.2.2:2222")));
    }

    #[test]
    fn a_stale_measurement_is_not_used() {
        let now = Instant::now();
        let samples = [measured("1.1.1.1:1111", false, 10, Duration::from_secs(60), now)];
        assert_eq!(choose(&samples, now, FRESH), None);
    }

    #[test]
    fn packets_arriving_beat_an_endpoint_that_only_claims_to_work() {
        let now = Instant::now();
        let samples = [claimed("5.5.5.5:54736"), carrying("5.5.5.5:51821", Duration::from_secs(1), now)];
        assert_eq!(choose(&samples, now, FRESH), Some(addr("5.5.5.5:51821")));
    }

    #[test]
    fn the_most_recent_arrival_wins_when_nothing_is_measured() {
        let now = Instant::now();
        let samples = [
            carrying("5.5.5.5:1111", Duration::from_secs(10), now),
            carrying("6.6.6.6:2222", Duration::from_secs(2), now),
        ];
        assert_eq!(choose(&samples, now, FRESH), Some(addr("6.6.6.6:2222")));
    }

    #[test]
    fn arrivals_that_stopped_are_not_used() {
        let now = Instant::now();
        let samples = [carrying("5.5.5.5:1111", Duration::from_secs(60), now)];
        assert_eq!(choose(&samples, now, FRESH), None);
    }

    #[test]
    fn a_measured_path_still_wins_over_a_fresher_arrival() {
        let now = Instant::now();
        let samples = [
            measured("1.1.1.1:1111", false, 30, Duration::from_secs(5), now),
            carrying("2.2.2.2:2222", Duration::ZERO, now),
        ];
        assert_eq!(choose(&samples, now, FRESH), Some(addr("1.1.1.1:1111")));
    }
}

mod public_endpoint {
    use super::path::public_ip;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_routable_address_is_the_one_traffic_appears_from() {
        assert_eq!(
            public_ip(&list(&["188.245.161.55:51821"])),
            Some("188.245.161.55".into())
        );
    }

    #[test]
    fn a_devices_own_lan_and_mesh_addresses_say_nothing_about_the_internet() {
        // real data from a device that reported its mesh address as an endpoint
        assert_eq!(
            public_ip(&list(&["217.237.74.6:51821", "100.64.0.2:51821"])),
            Some("217.237.74.6".into())
        );
        assert_eq!(public_ip(&list(&["192.168.1.107:54736", "10.0.0.4:1"])), None);
        assert_eq!(public_ip(&list(&["100.64.0.3:51821"])), None);
        assert_eq!(public_ip(&list(&["127.0.0.1:51821", "169.254.1.1:1"])), None);
    }

    #[test]
    fn nothing_to_report_is_not_a_guess() {
        assert_eq!(public_ip(&[]), None);
        assert_eq!(public_ip(&list(&["not-an-address", ""])), None);
    }
}

#[test]
fn service_never_carries_the_join_token() {
    let args = cli::service_args(&argv(&["join", "ngj_abc", "--install-service", "--share-internet"]));
    assert_eq!(args, vec!["--mesh", "--share-internet"]);
    let args = cli::service_args(&argv(&["--join-token", "ngj_abc", "--install-service"]));
    assert_eq!(args, vec!["--mesh"]);
}

#[test]
fn service_keeps_the_flags_it_was_installed_with() {
    let args = cli::service_args(&argv(&[
        "--mesh", "--install-service", "--magic-dns", "--network", "n-1",
        "--advertise-routes", "10.0.0.0/24", "-n", "box", "-t", "acct",
    ]));
    assert_eq!(
        args,
        vec!["--mesh", "--magic-dns", "--network", "n-1", "--advertise-routes", "10.0.0.0/24", "--token", "acct", "--name", "box"]
    );
}

fn saved_identity() -> meshtypes::MeshIdentity {
    serde_json::from_str(r#"{"token":"tok","public_key":"pk","network":{"id":"n-1"}}"#).unwrap()
}

#[test]
fn a_saved_identity_is_reused_only_when_it_still_applies() {
    let id = saved_identity();
    assert!(id.covers("pk", None, false));
    assert!(id.covers("pk", Some("n-1"), false));
    assert!(!id.covers("pk", Some("n-2"), false), "another network was asked for");
    assert!(!id.covers("other", None, false), "the machine key changed");
    let mut blank = saved_identity();
    blank.token.clear();
    assert!(!blank.covers("pk", None, false), "no token means nothing to reuse");
}

#[test]
fn joining_with_a_token_always_enrolls_afresh() {
    assert!(!saved_identity().covers("pk", None, true));
    assert!(!saved_identity().covers("pk", Some("n-1"), true));
}

#[test]
fn service_without_a_tunnel_of_its_own_is_the_idle_daemon() {
    assert_eq!(cli::service_args(&argv(&["--install-service"])), vec!["--daemon"]);
    assert_eq!(cli::service_args(&argv(&["--install-service", "--share-internet"])), vec!["--daemon"]);
    assert_eq!(
        cli::service_args(&argv(&["--mesh", "--install-service", "--share-internet"])),
        vec!["--mesh", "--share-internet"]
    );
}

#[path = "../src/protocol.rs"]
mod protocol;

#[test]
fn control_requests_round_trip_as_tagged_json() {
    let config = meshtypes::MeshConfig { device_name: "box".into(), ..Default::default() };
    let request = protocol::Request::Connect { config };
    let line = protocol::encode(&request).unwrap();
    assert!(line.starts_with(r#"{"cmd":"connect""#), "{}", line);
    assert_eq!(protocol::decode::<protocol::Request>(&line).unwrap(), request);
    assert_eq!(
        protocol::decode::<protocol::Request>(r#"{"cmd":"advertise_exit","enabled":true}"#).unwrap(),
        protocol::Request::AdvertiseExit { enabled: true }
    );
    assert!(protocol::decode::<protocol::Request>(r#"{"cmd":"format_disk"}"#).is_err());
}

#[test]
fn a_failed_reply_carries_its_error_and_a_good_one_its_snapshot() {
    let err = protocol::Response::from(Err("no tun".into()));
    assert_eq!(err.into_result().unwrap_err(), "no tun");
    let snapshot = protocol::Snapshot {
        version: "1.0.0".into(),
        state: protocol::EngineState::Connected,
        session: None,
        identity: None,
    };
    let line = protocol::encode(&protocol::Response::from(Ok(snapshot))).unwrap();
    let back: protocol::Response = protocol::decode(&line).unwrap();
    assert!(back.into_result().unwrap().connected());
    let state: protocol::EngineState = protocol::decode(r#"{"state":"failed","message":"x"}"#).unwrap();
    assert_eq!(state, protocol::EngineState::Failed { message: "x".into() });
}

#[test]
fn slow_requests_get_a_longer_deadline_than_status_polls() {
    let status = protocol::Request::Status.timeout();
    let connect = protocol::Request::Connect { config: Default::default() }.timeout();
    assert!(connect > status);
}
