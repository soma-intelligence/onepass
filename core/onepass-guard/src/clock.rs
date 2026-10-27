//! Injectable time source: wall time (seconds since the Unix epoch) for what
//! is stored on disk, monotonic time for what this process measures itself.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A source of wall and monotonic time.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch (wall clock, can jump backwards).
    fn now_unix(&self) -> i64;
    /// A monotonic instant (never goes backwards within this process).
    fn monotonic(&self) -> Instant;
}

/// A shared clock is a clock (lets a server and its control callback share
/// one).
impl<C: Clock + ?Sized> Clock for std::sync::Arc<C> {
    fn now_unix(&self) -> i64 {
        (**self).now_unix()
    }

    fn monotonic(&self) -> Instant {
        (**self).monotonic()
    }
}

/// The operating system clocks.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
        }
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

/// Test clocks.
pub mod testing {
    use super::Clock;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// A clock whose wall time is set by hand and whose monotonic time only
    /// moves forward when the test advances it.
    #[derive(Debug)]
    pub struct FakeClock {
        base: Instant,
        state: Mutex<(i64, Duration)>,
    }

    impl FakeClock {
        /// A clock at wall time `now_unix`.
        pub fn new(now_unix: i64) -> Self {
            FakeClock {
                base: Instant::now(),
                state: Mutex::new((now_unix, Duration::ZERO)),
            }
        }

        /// Sets the wall time only (for example to roll it back); the
        /// monotonic time does not move.
        pub fn set_now_unix(&self, now_unix: i64) {
            self.lock().0 = now_unix;
        }

        /// Advances both the wall time and the monotonic time by `d`.
        pub fn advance(&self, d: Duration) {
            let mut st = self.lock();
            st.0 =
                st.0.saturating_add(i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            st.1 += d;
        }

        /// Advances the monotonic time only.
        pub fn advance_monotonic(&self, d: Duration) {
            self.lock().1 += d;
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, (i64, Duration)> {
            self.state.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl Clock for FakeClock {
        fn now_unix(&self) -> i64 {
            self.lock().0
        }

        fn monotonic(&self) -> Instant {
            self.base + self.lock().1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeClock;
    use super::*;
    use std::time::Duration;

    #[test]
    fn system_clock_is_after_2026() {
        assert!(SystemClock.now_unix() > 1_767_225_600);
    }

    #[test]
    fn fake_clock_moves_only_when_told() {
        let c = FakeClock::new(1_000);
        let m0 = c.monotonic();
        assert_eq!(c.now_unix(), 1_000);
        c.advance(Duration::from_secs(30));
        assert_eq!(c.now_unix(), 1_030);
        assert_eq!(c.monotonic() - m0, Duration::from_secs(30));
        c.set_now_unix(10);
        assert_eq!(c.now_unix(), 10);
        assert_eq!(c.monotonic() - m0, Duration::from_secs(30));
        c.advance_monotonic(Duration::from_secs(5));
        assert_eq!(c.now_unix(), 10);
        assert_eq!(c.monotonic() - m0, Duration::from_secs(35));
    }
}
