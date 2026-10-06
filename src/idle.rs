use std::time::Duration;

pub struct IdleBackoff {
    floor: Duration,
    ceiling: Duration,
    current: Duration,
}

impl IdleBackoff {
    pub fn new(floor: Duration, ceiling: Duration) -> Self {
        Self {
            floor,
            ceiling: ceiling.max(floor),
            current: floor,
        }
    }

    pub fn reset(&mut self) {
        self.current = self.floor;
    }

    pub fn next(&mut self) -> Duration {
        let wait = self.current;
        self.current = (self.current * 2).min(self.ceiling);
        wait
    }
}
