#[path = "../src/exitnode.rs"]
#[allow(dead_code)]
mod exitnode;

use exitnode::{
    iptables_teardown, parse_cidr, parse_pf_token, validate_iface, ExitNodeState, ExitPlan, Family,
    PF_ANCHOR, UNSUPPORTED_PLATFORM,
};

const TUN: &str = "utun7";
const IFACE: &str = "en0";
const MESH_V4: &str = "100.64.0.0/10";
const MESH_V6: &str = "fd7a:115c:a1e0::/48";

fn plan_v4() -> ExitPlan {
    ExitPlan::new(TUN, MESH_V4, None, IFACE).unwrap()
}

fn plan_dual() -> ExitPlan {
    ExitPlan::new(TUN, MESH_V4, Some(MESH_V6), IFACE).unwrap()
}

fn joined(plan: &ExitPlan) -> Vec<String> {
    plan.iptables_plan().iter().map(|c| c.join(" ")).collect()
}

#[test]
fn parses_and_normalises_ipv4_networks() {
    assert_eq!(parse_cidr(MESH_V4, Family::V4).unwrap(), MESH_V4);
    assert_eq!(parse_cidr("10.8.0.37/24", Family::V4).unwrap(), "10.8.0.0/24");
    assert_eq!(parse_cidr("  192.168.5.9/16 ", Family::V4).unwrap(), "192.168.0.0/16");
    assert_eq!(parse_cidr("1.2.3.4/0", Family::V4).unwrap(), "0.0.0.0/0");
    assert_eq!(parse_cidr("1.2.3.4/32", Family::V4).unwrap(), "1.2.3.4/32");
}

#[test]
fn rejects_malformed_ipv4_networks() {
    for bad in ["", "10.0.0.0", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/x", "999.0.0.0/8", "fd00::/8", "10.0.0.0/8/8"] {
        assert!(parse_cidr(bad, Family::V4).is_err(), "accepted {:?}", bad);
    }
}

#[test]
fn parses_and_normalises_ipv6_networks() {
    assert_eq!(parse_cidr(MESH_V6, Family::V6).unwrap(), MESH_V6);
    assert_eq!(parse_cidr("fd00:dead:beef:1::99/64", Family::V6).unwrap(), "fd00:dead:beef:1::/64");
    assert_eq!(parse_cidr("fd00::1/0", Family::V6).unwrap(), "::/0");
}

#[test]
fn rejects_malformed_ipv6_networks() {
    for bad in ["", "fd00::", "fd00::/129", "10.0.0.0/8", "zz::/64"] {
        assert!(parse_cidr(bad, Family::V6).is_err(), "accepted {:?}", bad);
    }
}

#[test]
fn accepts_only_real_interface_names() {
    for good in [TUN, IFACE, "eth0", "wlp3s0", "br-0", "en0:1"] {
        assert_eq!(validate_iface(good).unwrap(), good);
    }
    for bad in ["", "en0 extra", "en0\nnat on en0 all", "$(id)", "en0;pfctl -d", "veryveryverylongiface"] {
        assert!(validate_iface(bad).is_err(), "accepted {:?}", bad);
    }
}

#[test]
fn plan_rejects_bad_input() {
    assert!(ExitPlan::new("", MESH_V4, None, IFACE).is_err());
    assert!(ExitPlan::new(TUN, "not-a-cidr", None, IFACE).is_err());
    assert!(ExitPlan::new(TUN, MESH_V4, Some("nope"), IFACE).is_err());
    assert!(ExitPlan::new(IFACE, MESH_V4, None, IFACE).is_err());
}

#[test]
fn plan_normalises_stored_networks() {
    let plan = ExitPlan::new(TUN, "100.64.7.1/10", Some("fd7a:115c:a1e0::5/48"), IFACE).unwrap();
    assert_eq!(plan.v4, MESH_V4);
    assert_eq!(plan.v6.as_deref(), Some(MESH_V6));
}

#[test]
fn iptables_plan_masquerades_the_mesh_out_of_the_uplink() {
    let rules = joined(&plan_v4());
    assert!(rules.iter().any(|r| r
        == &format!("iptables -t nat -A NEXGUARD-EXIT-NAT -s {} -o {} -j MASQUERADE", MESH_V4, IFACE)));
    assert!(rules.iter().any(|r| r == "iptables -t nat -A POSTROUTING -j NEXGUARD-EXIT-NAT"));
    assert!(rules.iter().any(|r| r == "iptables -A FORWARD -j NEXGUARD-EXIT-FWD"));
}

#[test]
fn iptables_plan_forwards_both_directions() {
    let rules = joined(&plan_v4());
    assert!(rules.iter().any(|r| r
        == &format!("iptables -A NEXGUARD-EXIT-FWD -i {} -o {} -s {} -j ACCEPT", TUN, IFACE, MESH_V4)));
    assert!(rules.iter().any(|r| r
        == &format!(
            "iptables -A NEXGUARD-EXIT-FWD -i {} -o {} -d {} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            IFACE, TUN, MESH_V4
        )));
}

#[test]
fn iptables_plan_clamps_mss_in_both_directions_before_accepting() {
    let rules = joined(&plan_v4());
    let clamps: Vec<usize> = rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r.contains("TCPMSS --clamp-mss-to-pmtu"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(clamps.len(), 2);
    for i in &clamps {
        assert!(rules[*i].contains("-p tcp --tcp-flags SYN,RST SYN"));
    }
    let first_accept = rules.iter().position(|r| r.ends_with("-j ACCEPT")).unwrap();
    assert!(clamps.iter().all(|i| *i < first_accept));
}

#[test]
fn iptables_plan_adds_a_matching_ipv6_ruleset() {
    let v4_only = joined(&plan_v4());
    let dual = joined(&plan_dual());
    assert_eq!(dual.len(), v4_only.len() * 2);

    let v6: Vec<&String> = dual.iter().filter(|r| r.starts_with("ip6tables ")).collect();
    assert_eq!(v6.len(), v4_only.len());
    assert!(v6.iter().any(|r| r
        == &&format!("ip6tables -t nat -A NEXGUARD-EXIT-NAT6 -s {} -o {} -j MASQUERADE", MESH_V6, IFACE)));
    assert!(v6.iter().any(|r| r.contains("TCPMSS --clamp-mss-to-pmtu")));
    assert!(!dual.iter().any(|r| r.starts_with("iptables ") && r.contains(MESH_V6)));
}

#[test]
fn chain_names_never_collide_with_the_server_nat_chains() {
    let names = ["VPN-NAT", "VPN-FWD", "VPN-NAT6", "VPN-FWD6", "NEXGUARD-KS"];
    for cmd in plan_dual().iptables_plan().into_iter().chain(iptables_teardown()) {
        for arg in &cmd {
            assert!(!names.contains(&arg.as_str()), "collides on {:?}", cmd);
        }
    }
}

#[test]
fn iptables_chain_names_fit_the_kernel_limit() {
    for cmd in iptables_teardown() {
        for arg in cmd.iter().filter(|a| a.starts_with("NEXGUARD-")) {
            assert!(arg.len() <= 28, "{} is too long", arg);
        }
    }
}

#[test]
fn teardown_unhooks_then_flushes_then_deletes_every_chain() {
    let teardown: Vec<String> = iptables_teardown().iter().map(|c| c.join(" ")).collect();
    let expected = [
        "iptables -t nat -D POSTROUTING -j NEXGUARD-EXIT-NAT",
        "iptables -t nat -F NEXGUARD-EXIT-NAT",
        "iptables -t nat -X NEXGUARD-EXIT-NAT",
        "iptables -D FORWARD -j NEXGUARD-EXIT-FWD",
        "iptables -F NEXGUARD-EXIT-FWD",
        "iptables -X NEXGUARD-EXIT-FWD",
        "ip6tables -t nat -D POSTROUTING -j NEXGUARD-EXIT-NAT6",
        "ip6tables -t nat -F NEXGUARD-EXIT-NAT6",
        "ip6tables -t nat -X NEXGUARD-EXIT-NAT6",
        "ip6tables -D FORWARD -j NEXGUARD-EXIT-FWD6",
        "ip6tables -F NEXGUARD-EXIT-FWD6",
        "ip6tables -X NEXGUARD-EXIT-FWD6",
    ];
    assert_eq!(teardown, expected);
}

#[test]
fn teardown_covers_every_chain_the_plan_creates() {
    let teardown: Vec<String> = iptables_teardown().concat();
    for cmd in plan_dual().iptables_plan() {
        for arg in cmd.iter().filter(|a| a.starts_with("NEXGUARD-")) {
            assert!(teardown.contains(arg), "{} is never removed", arg);
        }
    }
}

#[test]
fn pf_ruleset_nats_the_mesh_out_of_the_uplink() {
    let rules = plan_v4().pf_ruleset();
    assert!(rules.contains(&format!(
        "nat on {iface} inet from {mesh} to any -> ({iface})",
        iface = IFACE,
        mesh = MESH_V4
    )));
    assert!(rules.contains(&format!("pass in on {} inet from {} to any keep state", TUN, MESH_V4)));
    assert!(rules.contains(&format!("pass out on {iface} inet from ({iface}) to any keep state", iface = IFACE)));
}

#[test]
fn pf_ruleset_clamps_mss_on_the_tunnel() {
    let rules = plan_v4().pf_ruleset();
    let scrub = rules.lines().next().unwrap();
    assert!(scrub.starts_with(&format!("scrub on {} all max-mss ", TUN)));
    let mss: u16 = scrub.rsplit(' ').next().unwrap().parse().unwrap();
    assert!((1200..1400).contains(&mss), "implausible clamp {}", mss);
}

#[test]
fn pf_ruleset_orders_normalisation_then_translation_then_filtering() {
    let rules = plan_dual().pf_ruleset();
    let kind = |prefix: &str| rules.lines().position(|l| l.starts_with(prefix)).unwrap();
    assert!(kind("scrub") < kind("nat"));
    assert!(kind("nat") < kind("pass"));
    let last_nat = rules
        .lines()
        .enumerate()
        .filter(|(_, l)| l.starts_with("nat"))
        .map(|(i, _)| i)
        .last()
        .unwrap();
    assert!(last_nat < kind("pass"));
    assert!(rules.ends_with('\n'));
}

#[test]
fn pf_ruleset_adds_ipv6_only_when_requested() {
    let v4_only = plan_v4().pf_ruleset();
    assert!(!v4_only.contains("inet6"));
    assert!(!v4_only.contains(MESH_V6));

    let dual = plan_dual().pf_ruleset();
    assert!(dual.contains(&format!(
        "nat on {iface} inet6 from {mesh} to any -> ({iface})",
        iface = IFACE,
        mesh = MESH_V6
    )));
    assert_eq!(dual.lines().filter(|l| l.starts_with("scrub")).count(), 1);
    assert_eq!(dual.lines().filter(|l| l.starts_with("nat")).count(), 2);
    assert_eq!(dual.lines().filter(|l| l.starts_with("pass")).count(), 4);
}

#[test]
fn pf_ruleset_cannot_be_injected_through_its_inputs() {
    assert!(ExitPlan::new("utun7\nblock all", MESH_V4, None, IFACE).is_err());
    assert!(ExitPlan::new(TUN, MESH_V4, None, "en0\npass all").is_err());
    let rules = plan_dual().pf_ruleset();
    assert!(rules
        .lines()
        .all(|l| l.is_empty() || l.starts_with("scrub") || l.starts_with("nat") || l.starts_with("pass")));
}

#[test]
fn pf_anchor_nests_under_the_system_anchor_point() {
    assert!(PF_ANCHOR.starts_with("com.apple/"));
    assert!(!PF_ANCHOR.ends_with('/'));
    assert!(PF_ANCHOR.len() > "com.apple/".len());
}

#[test]
fn pf_token_is_read_from_either_stream_and_validated() {
    assert_eq!(parse_pf_token("pf enabled\nToken : 14281274918\n").as_deref(), Some("14281274918"));
    assert_eq!(parse_pf_token("Token\t:\t42").as_deref(), Some("42"));
    for bad in ["", "pf enabled\n", "Token : \n", "Token : abc", "Token : 12; pfctl -d"] {
        assert_eq!(parse_pf_token(bad), None, "accepted {:?}", bad);
    }
}

#[test]
fn support_is_declared_only_for_linux_and_macos() {
    assert_eq!(
        ExitNodeState::is_supported(),
        cfg!(any(target_os = "linux", target_os = "macos"))
    );
}

#[test]
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unsupported_platforms_refuse_to_activate() {
    let err = ExitNodeState::activate(TUN, MESH_V4, None).unwrap_err();
    assert_eq!(err, UNSUPPORTED_PLATFORM);
}

#[test]
fn the_unsupported_message_names_the_platform_limit() {
    assert!(UNSUPPORTED_PLATFORM.contains("not supported"));
}
