//! Rate limits and the approval-fatigue guard (spec 4.3), plus prompt
//! coalescing: per client, in the server's memory.
//!
//! [`Throttle`] counts prompts and secret requests over a sliding minute and
//! puts a client in a cooling-down period after a run of user denials.
//! [`PromptGate`] makes identical requests that arrive while one prompt is
//! pending wait for that prompt and share its decision instead of opening
//! another one.

use crate::approval::{ApprovalRequest, Approver, Decision};
use crate::clock::Clock;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Length of the sliding window of the rate limits.
const WINDOW: Duration = Duration::from_secs(60);

/// Beyond this many tracked clients, idle ones are dropped on the next call.
const PRUNE_ABOVE: usize = 256;

/// Thresholds of one surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Prompts shown per client per minute; beyond, refused without a prompt.
    pub prompts_per_min: u32,
    /// Secret requests (MCP) or signatures (SSH) per client per minute.
    pub secret_per_min: u32,
    /// User denials in a row that put the client in a cooling-down period.
    pub denials_before_cooldown: u32,
    /// How long a client is refused without a prompt after those denials.
    pub cooldown: Duration,
}

impl Limits {
    /// MCP server: 6 prompts, 30 secret requests per minute, 3 denials then
    /// 10 minutes of cooling down.
    pub fn mcp() -> Limits {
        Limits {
            prompts_per_min: 6,
            secret_per_min: 30,
            denials_before_cooldown: 3,
            cooldown: Duration::from_secs(10 * 60),
        }
    }

    /// SSH agent: 6 prompts, 60 signatures per minute, 3 denials then
    /// 10 minutes of cooling down.
    pub fn ssh() -> Limits {
        Limits {
            prompts_per_min: 6,
            secret_per_min: 60,
            denials_before_cooldown: 3,
            cooldown: Duration::from_secs(10 * 60),
        }
    }
}

/// What is being counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A prompt about to be shown to the user.
    Prompt,
    /// A request that returns or uses a secret (or an SSH signature).
    Secret,
}

/// Answer of [`Throttle::admit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Go ahead (the request has been counted).
    Ok,
    /// Over the per-minute limit: refuse without a prompt (`rate_limited`).
    RateLimited,
    /// The client is cooling down after repeated denials: refuse without a
    /// prompt (`client_cooling_down`). `first_notice` is true exactly once
    /// per cooling-down period, so the terminal is told only once.
    CoolingDown {
        /// End of the period (monotonic).
        until: Instant,
        /// True for the first refusal of this period.
        first_notice: bool,
    },
}

#[derive(Default)]
struct ClientState {
    prompts: VecDeque<Instant>,
    secrets: VecDeque<Instant>,
    denials: u32,
    cooling_until: Option<Instant>,
    noticed: bool,
}

impl ClientState {
    fn idle(&self) -> bool {
        self.prompts.is_empty()
            && self.secrets.is_empty()
            && self.denials == 0
            && self.cooling_until.is_none()
    }
}

/// Per-client counters of one surface, in memory. Times come from the
/// monotonic clock, so a wall-clock change neither lifts nor extends a limit.
pub struct Throttle {
    limits: Limits,
    clients: HashMap<String, ClientState>,
}

impl Throttle {
    /// A throttle with no history.
    pub fn new(limits: Limits) -> Throttle {
        Throttle {
            limits,
            clients: HashMap::new(),
        }
    }

    /// The thresholds in use.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Decides whether `client_id` may go on with a request of `kind`, and
    /// counts it when it may. A refused request is not counted, so a client
    /// that keeps retrying does not extend its own limit.
    pub fn admit(&mut self, clock: &dyn Clock, client_id: &str, kind: Kind) -> Admit {
        let now = clock.monotonic();
        self.prune(now);
        let limits = self.limits;
        let st = self.clients.entry(client_id.to_owned()).or_default();
        if let Some(until) = st.cooling_until {
            if now < until {
                let first_notice = !st.noticed;
                st.noticed = true;
                return Admit::CoolingDown {
                    until,
                    first_notice,
                };
            }
            st.cooling_until = None;
            st.noticed = false;
        }
        let (window, max) = match kind {
            Kind::Prompt => (&mut st.prompts, limits.prompts_per_min),
            Kind::Secret => (&mut st.secrets, limits.secret_per_min),
        };
        expire(window, now);
        if window.len() >= max as usize {
            return Admit::RateLimited;
        }
        window.push_back(now);
        Admit::Ok
    }

    /// Records the user's answer to a prompt of `client_id`: a denial adds to
    /// the run of denials (which starts a cooling-down period when it reaches
    /// the threshold), anything else ends the run.
    pub fn record_decision(&mut self, clock: &dyn Clock, client_id: &str, denied: bool) {
        let now = clock.monotonic();
        let limits = self.limits;
        let st = self.clients.entry(client_id.to_owned()).or_default();
        if !denied {
            st.denials = 0;
            return;
        }
        st.denials = st.denials.saturating_add(1);
        if st.denials >= limits.denials_before_cooldown {
            st.denials = 0;
            st.cooling_until = Some(now + limits.cooldown);
            st.noticed = false;
        }
    }

    /// Drops the state of idle clients once many are tracked.
    fn prune(&mut self, now: Instant) {
        if self.clients.len() <= PRUNE_ABOVE {
            return;
        }
        self.clients.retain(|_, st| {
            expire(&mut st.prompts, now);
            expire(&mut st.secrets, now);
            if st.cooling_until.is_some_and(|u| u <= now) {
                st.cooling_until = None;
            }
            !st.idle()
        });
    }
}

/// Removes the instants older than the window.
fn expire(window: &mut VecDeque<Instant>, now: Instant) {
    while window
        .front()
        .is_some_and(|&t| now.saturating_duration_since(t) >= WINDOW)
    {
        window.pop_front();
    }
}

/// One pending prompt that later identical requests wait for.
#[derive(Default)]
struct Slot {
    decision: Mutex<Option<Decision>>,
    done: Condvar,
    waiters: Mutex<usize>,
}

/// Wraps an approver so that a request identical to one whose prompt is
/// still pending (same client, same canonical key) waits for that prompt and
/// gets the same decision, instead of opening a second prompt.
pub struct PromptGate<A: Approver> {
    inner: A,
    pending: Mutex<HashMap<(String, String), Arc<Slot>>>,
}

/// Fills the slot (with `Deny` if the prompt did not finish, for example on
/// a panic), wakes the waiters and forgets the slot.
struct Publish<'a, A: Approver> {
    gate: &'a PromptGate<A>,
    id: (String, String),
    slot: Arc<Slot>,
    decision: Option<Decision>,
}

impl<A: Approver> Drop for Publish<'_, A> {
    fn drop(&mut self) {
        // Forget the slot first: a request arriving after the decision opens
        // its own prompt.
        lock(&self.gate.pending).remove(&self.id);
        *lock(&self.slot.decision) = Some(self.decision.unwrap_or(Decision::Deny));
        self.slot.done.notify_all();
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl<A: Approver> PromptGate<A> {
    /// Wraps `inner`.
    pub fn new(inner: A) -> Self {
        PromptGate {
            inner,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// The wrapped approver.
    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// Asks the wrapped approver about `req` from `client_id`, unless a
    /// prompt for the same `(client_id, key)` is pending: then waits for it
    /// and returns its decision.
    pub fn approve(&self, client_id: &str, key: &str, req: &ApprovalRequest) -> Decision {
        let id = (client_id.to_owned(), key.to_owned());
        let (slot, leader) = {
            let mut pending = lock(&self.pending);
            match pending.get(&id) {
                Some(slot) => (slot.clone(), false),
                None => {
                    let slot = Arc::new(Slot::default());
                    pending.insert(id.clone(), slot.clone());
                    (slot, true)
                }
            }
        };
        if !leader {
            *lock(&slot.waiters) += 1;
            let mut decision = lock(&slot.decision);
            while decision.is_none() {
                decision = slot.done.wait(decision).unwrap_or_else(|e| e.into_inner());
            }
            return decision.unwrap_or(Decision::Deny);
        }
        let mut publish = Publish {
            gate: self,
            id,
            slot,
            decision: None,
        };
        let decision = self.inner.approve(req);
        publish.decision = Some(decision);
        decision
    }

    /// Number of requests waiting for the pending prompt of
    /// `(client_id, key)` (0 when none is pending).
    pub fn waiting(&self, client_id: &str, key: &str) -> usize {
        let pending = lock(&self.pending);
        pending
            .get(&(client_id.to_owned(), key.to_owned()))
            .map_or(0, |s| *lock(&s.waiters))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::Surface;
    use crate::approval::testing::ScriptedApprover;
    use crate::clock::testing::FakeClock;
    use std::sync::Barrier;

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn limits_have_the_spec_values() {
        let m = Limits::mcp();
        assert_eq!(
            (
                m.prompts_per_min,
                m.secret_per_min,
                m.denials_before_cooldown
            ),
            (6, 30, 3)
        );
        assert_eq!(m.cooldown, Duration::from_secs(600));
        let s = Limits::ssh();
        assert_eq!(
            (
                s.prompts_per_min,
                s.secret_per_min,
                s.denials_before_cooldown
            ),
            (6, 60, 3)
        );
        assert_eq!(s.cooldown, Duration::from_secs(600));
    }

    #[test]
    fn seventh_prompt_in_a_minute_is_rate_limited() {
        let clock = FakeClock::new(1_000);
        let mut t = Throttle::new(Limits::mcp());
        for _ in 0..6 {
            assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::Ok);
            clock.advance(Duration::from_secs(5));
        }
        assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::RateLimited);
        // Refusals are not counted: once the first prompt leaves the window,
        // one more is allowed.
        clock.advance(MIN - Duration::from_secs(30));
        assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::Ok);
        assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::RateLimited);
        clock.advance(MIN);
        assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::Ok);
    }

    #[test]
    fn secret_rate_is_per_surface() {
        let clock = FakeClock::new(1_000);
        for (limits, max) in [(Limits::mcp(), 30), (Limits::ssh(), 60)] {
            let mut t = Throttle::new(limits);
            for _ in 0..max {
                assert_eq!(t.admit(&clock, "c", Kind::Secret), Admit::Ok);
            }
            assert_eq!(t.admit(&clock, "c", Kind::Secret), Admit::RateLimited);
            // Secrets and prompts are counted apart.
            assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::Ok);
            clock.advance(MIN);
            assert_eq!(t.admit(&clock, "c", Kind::Secret), Admit::Ok);
        }
    }

    #[test]
    fn three_denials_cool_down_ten_minutes() {
        let clock = FakeClock::new(1_000);
        let mut t = Throttle::new(Limits::mcp());
        t.record_decision(&clock, "c", true);
        t.record_decision(&clock, "c", true);
        assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::Ok);
        let start = clock.monotonic();
        t.record_decision(&clock, "c", true);
        let until = start + Duration::from_secs(600);
        assert_eq!(
            t.admit(&clock, "c", Kind::Prompt),
            Admit::CoolingDown {
                until,
                first_notice: true
            }
        );
        // Secrets are refused too while cooling down.
        assert!(matches!(
            t.admit(&clock, "c", Kind::Secret),
            Admit::CoolingDown { .. }
        ));
        clock.advance(Duration::from_secs(599));
        assert!(matches!(
            t.admit(&clock, "c", Kind::Prompt),
            Admit::CoolingDown { .. }
        ));
        clock.advance(Duration::from_secs(1));
        assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::Ok);
        // The run starts again from zero after the period.
        t.record_decision(&clock, "c", true);
        t.record_decision(&clock, "c", true);
        assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::Ok);
    }

    #[test]
    fn an_allow_breaks_the_run_of_denials() {
        let clock = FakeClock::new(1_000);
        let mut t = Throttle::new(Limits::mcp());
        t.record_decision(&clock, "c", true);
        t.record_decision(&clock, "c", true);
        t.record_decision(&clock, "c", false);
        t.record_decision(&clock, "c", true);
        t.record_decision(&clock, "c", true);
        assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::Ok);
    }

    #[test]
    fn cooldown_first_notice_only_once() {
        let clock = FakeClock::new(1_000);
        let mut t = Throttle::new(Limits::ssh());
        for _ in 0..3 {
            t.record_decision(&clock, "c", true);
        }
        let notices: Vec<bool> = (0..4)
            .map(|_| match t.admit(&clock, "c", Kind::Prompt) {
                Admit::CoolingDown { first_notice, .. } => first_notice,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(notices, [true, false, false, false]);
        // A new period gets its own single notice.
        clock.advance(Duration::from_secs(600));
        assert_eq!(t.admit(&clock, "c", Kind::Prompt), Admit::Ok);
        for _ in 0..3 {
            t.record_decision(&clock, "c", true);
        }
        assert!(matches!(
            t.admit(&clock, "c", Kind::Prompt),
            Admit::CoolingDown {
                first_notice: true,
                ..
            }
        ));
    }

    #[test]
    fn clients_are_isolated() {
        let clock = FakeClock::new(1_000);
        let mut t = Throttle::new(Limits::mcp());
        for _ in 0..6 {
            assert_eq!(t.admit(&clock, "a", Kind::Prompt), Admit::Ok);
        }
        assert_eq!(t.admit(&clock, "a", Kind::Prompt), Admit::RateLimited);
        assert_eq!(t.admit(&clock, "b", Kind::Prompt), Admit::Ok);
        for _ in 0..3 {
            t.record_decision(&clock, "a", true);
        }
        assert!(matches!(
            t.admit(&clock, "a", Kind::Secret),
            Admit::CoolingDown { .. }
        ));
        assert_eq!(t.admit(&clock, "b", Kind::Secret), Admit::Ok);
    }

    #[test]
    fn wall_clock_changes_do_not_lift_limits() {
        let clock = FakeClock::new(1_000);
        let mut t = Throttle::new(Limits::mcp());
        for _ in 0..3 {
            t.record_decision(&clock, "c", true);
        }
        clock.set_now_unix(1_000_000);
        assert!(matches!(
            t.admit(&clock, "c", Kind::Prompt),
            Admit::CoolingDown { .. }
        ));
    }

    #[test]
    fn idle_clients_are_pruned() {
        let clock = FakeClock::new(1_000);
        let mut t = Throttle::new(Limits::mcp());
        for i in 0..300 {
            t.admit(&clock, &format!("c{i}"), Kind::Prompt);
        }
        clock.advance(MIN);
        t.admit(&clock, "last", Kind::Prompt);
        assert_eq!(t.clients.len(), 1);
    }

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            surface: Surface::Mcp,
            client: "c".into(),
            action: "run_with_secrets".into(),
            details: vec![],
            targets: vec![],
            remember_allowed: true,
        }
    }

    /// Waits (at most 10 s) until a request waits on the pending prompt of
    /// `("c", "k")`.
    fn wait_for_waiter<A: Approver>(gate: &PromptGate<A>) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while gate.waiting("c", "k") == 0 {
            assert!(Instant::now() < deadline, "the second request never waited");
            std::thread::yield_now();
        }
    }

    /// A scripted approver that blocks inside `approve` until released.
    struct BarrierApprover {
        entered: Barrier,
        release: Barrier,
        inner: ScriptedApprover,
    }

    impl Approver for BarrierApprover {
        fn approve(&self, req: &ApprovalRequest) -> Decision {
            self.entered.wait();
            self.release.wait();
            self.inner.approve(req)
        }
    }

    #[test]
    fn identical_pending_requests_share_one_prompt() {
        let gate = Arc::new(PromptGate::new(BarrierApprover {
            entered: Barrier::new(2),
            release: Barrier::new(2),
            inner: ScriptedApprover::new(vec![
                Decision::AllowFor(Duration::from_secs(300)),
                Decision::Deny,
            ]),
        }));
        let leader = {
            let gate = gate.clone();
            std::thread::spawn(move || gate.approve("c", "k", &req()))
        };
        // The leader's prompt is now open.
        gate.inner().entered.wait();
        let follower = {
            let gate = gate.clone();
            std::thread::spawn(move || gate.approve("c", "k", &req()))
        };
        wait_for_waiter(&*gate);
        gate.inner().release.wait();
        let allow = Decision::AllowFor(Duration::from_secs(300));
        assert_eq!(leader.join().unwrap(), allow);
        assert_eq!(follower.join().unwrap(), allow);
        assert_eq!(gate.inner().inner.calls().len(), 1);
        assert_eq!(gate.waiting("c", "k"), 0);
    }

    #[test]
    fn different_requests_or_clients_get_their_own_prompt() {
        let gate = PromptGate::new(ScriptedApprover::new(vec![
            Decision::AllowOnce,
            Decision::Deny,
            Decision::AllowOnce,
        ]));
        assert_eq!(gate.approve("c", "k", &req()), Decision::AllowOnce);
        // Not pending any more: a new identical request prompts again.
        assert_eq!(gate.approve("c", "k", &req()), Decision::Deny);
        assert_eq!(gate.approve("d", "k", &req()), Decision::AllowOnce);
        assert_eq!(gate.inner().calls().len(), 3);
    }

    /// An approver that panics: the waiters must be released with `Deny`.
    struct PanickingApprover {
        entered: Barrier,
        release: Barrier,
    }

    impl Approver for PanickingApprover {
        fn approve(&self, _req: &ApprovalRequest) -> Decision {
            self.entered.wait();
            self.release.wait();
            panic!("approver failure");
        }
    }

    #[test]
    fn a_failed_prompt_denies_its_waiters() {
        let gate = Arc::new(PromptGate::new(PanickingApprover {
            entered: Barrier::new(2),
            release: Barrier::new(2),
        }));
        let leader = {
            let gate = gate.clone();
            std::thread::spawn(move || gate.approve("c", "k", &req()))
        };
        gate.inner().entered.wait();
        let follower = {
            let gate = gate.clone();
            std::thread::spawn(move || gate.approve("c", "k", &req()))
        };
        wait_for_waiter(&*gate);
        gate.inner().release.wait();
        assert!(leader.join().is_err());
        assert_eq!(follower.join().unwrap(), Decision::Deny);
    }
}
