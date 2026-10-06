#[path = "../src/idle.rs"]
mod idle;

use idle::IdleBackoff;
use std::time::Duration;

const FLOOR: Duration = Duration::from_micros(50);
const CEILING: Duration = Duration::from_millis(1);

#[test]
fn the_first_idle_wait_is_the_floor_so_a_fresh_burst_stays_fast() {
    let mut idle = IdleBackoff::new(FLOOR, CEILING);
    assert_eq!(idle.next(), FLOOR);
}

#[test]
fn consecutive_idle_waits_double_until_the_ceiling() {
    let mut idle = IdleBackoff::new(FLOOR, CEILING);
    let waits: Vec<Duration> = (0..7).map(|_| idle.next()).collect();
    assert_eq!(
        waits,
        [50, 100, 200, 400, 800, 1000, 1000].map(Duration::from_micros)
    );
}

#[test]
fn traffic_resets_the_wait_back_to_the_floor() {
    let mut idle = IdleBackoff::new(FLOOR, CEILING);
    (0..10).for_each(|_| {
        idle.next();
    });
    idle.reset();
    assert_eq!(idle.next(), FLOOR);
}

#[test]
fn a_ceiling_below_the_floor_never_shortens_the_wait() {
    let mut idle = IdleBackoff::new(CEILING, FLOOR);
    assert_eq!(idle.next(), CEILING);
    assert_eq!(idle.next(), CEILING);
}

#[test]
fn an_idle_second_costs_about_a_thousand_wakeups_not_twenty_thousand() {
    let mut idle = IdleBackoff::new(FLOOR, CEILING);
    let mut elapsed = Duration::ZERO;
    let mut wakeups = 0;
    while elapsed < Duration::from_secs(1) {
        elapsed += idle.next();
        wakeups += 1;
    }
    assert!(wakeups <= 1_010, "{wakeups} wakeups per idle second");
}
