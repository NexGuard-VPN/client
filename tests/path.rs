#[path = "../src/path.rs"]
mod path;

use path::{owners, trial_order, AddressClaim};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const SHARED_NAT: &str = "217.237.66.107:51821";
const LAPTOP: usize = 0;
const ROBOT: usize = 1;

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn claim(owner: usize, seen: Option<Instant>) -> AddressClaim {
    AddressClaim { addr: addr(SHARED_NAT), owner, seen }
}

#[test]
fn a_shared_address_belongs_to_the_peer_that_proved_it_last() {
    let now = Instant::now();
    let stale = now - Duration::from_secs(600);
    let table = owners(vec![claim(LAPTOP, Some(now)), claim(ROBOT, Some(stale))]);
    assert_eq!(table[&addr(SHARED_NAT)], LAPTOP);
}

#[test]
fn listing_order_does_not_decide_a_shared_address() {
    let now = Instant::now();
    let stale = now - Duration::from_secs(600);
    let table = owners(vec![claim(ROBOT, Some(stale)), claim(LAPTOP, Some(now))]);
    assert_eq!(table[&addr(SHARED_NAT)], LAPTOP);
}

#[test]
fn a_proven_claim_beats_one_only_advertised() {
    let table = owners(vec![claim(LAPTOP, Some(Instant::now())), claim(ROBOT, None)]);
    assert_eq!(table[&addr(SHARED_NAT)], LAPTOP);
}

#[test]
fn trial_starts_with_the_hinted_peer_and_still_reaches_every_other() {
    assert_eq!(trial_order(Some(2), 4).collect::<Vec<_>>(), vec![2, 0, 1, 3]);
}

#[test]
fn trial_without_a_hint_tries_every_peer_once() {
    assert_eq!(trial_order(None, 3).collect::<Vec<_>>(), vec![0, 1, 2]);
}

#[test]
fn a_hint_beyond_the_peer_list_is_ignored() {
    assert_eq!(trial_order(Some(7), 2).collect::<Vec<_>>(), vec![0, 1]);
}
