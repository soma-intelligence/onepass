//! Rate limits and the approval-fatigue guard (spec 4.3), plus prompt
//! coalescing: per client, in the server's memory.
//!
//! [`Throttle`] counts prompts and secret requests over a sliding minute and
//! puts a client in a cooling-down period after a run of user denials.
//! [`PromptGate`] makes identical requests that arrive while one prompt is
//! pending wait for that prompt instead of opening another one (an
//! `AllowOnce` answer is never shared).

use crate::approval::{ApprovalRequest, Approver, Decision};
use crate::clock::Clock;
use std::collections::{HashMap, VecDeque};
use std::sync::{Condvar, Mutex};
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

    /// `base` tightened by the environment (see [`LIMIT_ENV_VARS`]): each
    /// variable may only make its limit stricter (fewer prompts, secrets or
    /// denials, a longer cooldown); a looser value is clamped to `base`.
    /// `Err` on a value that is not a positive integer.
    pub fn from_env(base: Limits) -> Result<Limits, String> {
        Limits::from_vars(base, |name| std::env::var(name).ok())
    }

    /// Pure form of [`Limits::from_env`]: `get` returns a variable's value.
    pub fn from_vars(base: Limits, get: impl Fn(&str) -> Option<String>) -> Result<Limits, String> {
        let read = |name: &str| -> Result<Option<u64>, String> {
            match get(name) {
                None => Ok(None),
                Some(v) => match v.trim().parse::<u64>() {
                    Ok(n) if n > 0 => Ok(Some(n)),
                    _ => Err(format!("{name} must be a positive integer")),
                },
            }
        };
        let fewer = |name: &str, base: u32| -> Result<u32, String> {
            Ok(read(name)?.map_or(base, |n| u32::try_from(n).unwrap_or(u32::MAX).min(base)))
        };
        let cooldown = match read(LIMIT_ENV_VARS[3])? {
            None => base.cooldown,
            Some(secs) => Duration::from_secs(secs.min(MAX_COOLDOWN_SECS)).max(base.cooldown),
        };
        Ok(Limits {
            prompts_per_min: fewer(LIMIT_ENV_VARS[0], base.prompts_per_min)?,
            secret_per_min: fewer(LIMIT_ENV_VARS[1], base.secret_per_min)?,
            denials_before_cooldown: fewer(LIMIT_ENV_VARS[2], base.denials_before_cooldown)?,
            cooldown,
        })
    }
}

/// Variables read by [`Limits::from_env`]: prompts per minute, secret
/// requests (or signatures) per minute, denials in a row before the
/// cooldown, cooldown in seconds.
pub const LIMIT_ENV_VARS: [&str; 4] = [
    "ONEPASS_LIMIT_PROMPTS_PER_MIN",
    "ONEPASS_LIMIT_SECRETS_PER_MIN",
    "ONEPASS_LIMIT_DENIALS",
    "ONEPASS_LIMIT_COOLDOWN_SECS",
];

/// Longest cooldown accepted from the environment (24 h).
const MAX_COOLDOWN_SECS: u64 = 24 * 60 * 60;

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

/// Result of [`PromptGate::approve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gated {
    /// The decision that applies to this request.
    pub decision: Decision,
    /// True when no prompt was shown for this request: it joined the prompt
    /// of an identical pending request (or timed out waiting for it, then
    /// `decision` is `Deny`).
    pub joined: bool,
}

/// What a waiting request learns when the prompt it waits for ends.
#[derive(Clone, Copy)]
enum Turn {
    /// Take this decision without a prompt.
    Join(Decision),
    /// Prompt yourself (the previous prompt allowed only once).
    Lead,
}

/// Per `(client, key)` state: whether a prompt is shown, the requests
/// waiting in arrival order, and the answers left for them.
#[derive(Default)]
struct KeyState {
    prompting: bool,
    queue: VecDeque<u64>,
    turns: HashMap<u64, Turn>,
    next_ticket: u64,
}

impl KeyState {
    fn idle(&self) -> bool {
        !self.prompting && self.queue.is_empty() && self.turns.is_empty()
    }
}

type Pending = HashMap<(String, String), KeyState>;

/// Coalesces identical approval requests (same client, same canonical key)
/// that arrive while a prompt for one of them is shown.
///
/// - The first request prompts (it leads). Later identical requests wait,
///   in arrival order, at most `wait` (then `Deny`, joined).
/// - When the prompt ends with `Deny` or `AllowFor(d)`, every waiting
///   request gets that decision, marked `joined`.
/// - When it ends with `AllowOnce`, that answer covers the leader only: the
///   oldest waiting request leads the next prompt, the others keep waiting.
///   One click never authorizes more than one action.
///
/// Callers record one denial per prompt shown: they call
/// [`Throttle::record_decision`] only when `joined` is false, and audit a
/// joined decision with the decision label `"joined"`.
pub struct PromptGate<A: Approver> {
    inner: A,
    wait: Duration,
    pending: Mutex<Pending>,
    changed: Condvar,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Publishes the leader's decision (`Deny` if the prompt did not finish,
/// for example on a panic) to the waiting requests.
struct Publish<'a, A: Approver> {
    gate: &'a PromptGate<A>,
    id: &'a (String, String),
    decision: Option<Decision>,
}

impl<A: Approver> Drop for Publish<'_, A> {
    fn drop(&mut self) {
        let decision = self.decision.unwrap_or(Decision::Deny);
        let mut pending = lock(&self.gate.pending);
        if let Some(st) = pending.get_mut(self.id) {
            match decision {
                Decision::AllowOnce => match st.queue.pop_front() {
                    // The prompt stays "shown" for the next leader.
                    Some(next) => {
                        st.turns.insert(next, Turn::Lead);
                    }
                    None => st.prompting = false,
                },
                shared => {
                    for t in st.queue.drain(..) {
                        st.turns.insert(t, Turn::Join(shared));
                    }
                    st.prompting = false;
                }
            }
            if st.idle() {
                pending.remove(self.id);
            }
        }
        drop(pending);
        self.gate.changed.notify_all();
    }
}

impl<A: Approver> PromptGate<A> {
    /// Wraps `inner`. A waiting request waits at most `wait` (use the
    /// approver's own answer timeout) before it is denied.
    pub fn new(inner: A, wait: Duration) -> Self {
        PromptGate {
            inner,
            wait,
            pending: Mutex::new(HashMap::new()),
            changed: Condvar::new(),
        }
    }

    /// The wrapped approver.
    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// Asks about `req` from `client_id`, or waits for the pending prompt of
    /// an identical request (same `client_id` and canonical `key`); see the
    /// type documentation for how the decision is shared.
    pub fn approve(&self, client_id: &str, key: &str, req: &ApprovalRequest) -> Gated {
        let id = (client_id.to_owned(), key.to_owned());
        let mut pending = lock(&self.pending);
        let st = pending.entry(id.clone()).or_default();
        if st.prompting {
            let ticket = st.next_ticket;
            st.next_ticket += 1;
            st.queue.push_back(ticket);
            let deadline = Instant::now() + self.wait;
            loop {
                let st = pending.entry(id.clone()).or_default();
                if let Some(turn) = st.turns.remove(&ticket) {
                    if st.idle() {
                        pending.remove(&id);
                    }
                    match turn {
                        Turn::Join(decision) => {
                            return Gated {
                                decision,
                                joined: true,
                            };
                        }
                        Turn::Lead => break,
                    }
                }
                let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                    st.queue.retain(|&t| t != ticket);
                    if st.idle() {
                        pending.remove(&id);
                    }
                    return Gated {
                        decision: Decision::Deny,
                        joined: true,
                    };
                };
                pending = self
                    .changed
                    .wait_timeout(pending, left)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        } else {
            st.prompting = true;
        }
        drop(pending);
        let mut publish = Publish {
            gate: self,
            id: &id,
            decision: None,
        };
        let decision = self.inner.approve(req);
        publish.decision = Some(decision);
        drop(publish);
        Gated {
            decision,
            joined: false,
        }
    }

    /// Number of requests waiting for the prompt of `(client_id, key)`.
    pub fn waiting(&self, client_id: &str, key: &str) -> usize {
        lock(&self.pending)
            .get(&(client_id.to_owned(), key.to_owned()))
            .map_or(0, |st| st.queue.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::Surface;
    use crate::approval::testing::ScriptedApprover;
    use crate::clock::testing::FakeClock;
    use std::sync::{Arc, Barrier};

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
            client_verified: false,
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

    const LONG: Duration = Duration::from_secs(60);

    fn barrier_gate(answers: Vec<Decision>, wait: Duration) -> Arc<PromptGate<BarrierApprover>> {
        Arc::new(PromptGate::new(
            BarrierApprover {
                entered: Barrier::new(2),
                release: Barrier::new(2),
                inner: ScriptedApprover::new(answers),
            },
            wait,
        ))
    }

    fn spawn_approve(gate: &Arc<PromptGate<BarrierApprover>>) -> std::thread::JoinHandle<Gated> {
        let gate = gate.clone();
        std::thread::spawn(move || gate.approve("c", "k", &req()))
    }

    /// Leader prompting, one identical follower waiting; the leader's prompt
    /// is then answered with the first scripted answer.
    fn leader_and_follower(
        answers: Vec<Decision>,
    ) -> (
        Arc<PromptGate<BarrierApprover>>,
        std::thread::JoinHandle<Gated>,
        std::thread::JoinHandle<Gated>,
    ) {
        let gate = barrier_gate(answers, LONG);
        let leader = spawn_approve(&gate);
        // The leader's prompt is now open.
        gate.inner().entered.wait();
        let follower = spawn_approve(&gate);
        wait_for_waiter(&gate);
        gate.inner().release.wait();
        (gate, leader, follower)
    }

    fn shown(decision: Decision) -> Gated {
        Gated {
            decision,
            joined: false,
        }
    }

    fn joined(decision: Decision) -> Gated {
        Gated {
            decision,
            joined: true,
        }
    }

    #[test]
    fn identical_pending_requests_share_one_prompt() {
        let allow = Decision::AllowFor(Duration::from_secs(300));
        let (gate, leader, follower) = leader_and_follower(vec![allow, Decision::Deny]);
        assert_eq!(leader.join().unwrap(), shown(allow));
        assert_eq!(follower.join().unwrap(), joined(allow));
        assert_eq!(gate.inner().inner.calls().len(), 1);
        assert_eq!(gate.waiting("c", "k"), 0);
        assert!(lock(&gate.pending).is_empty());
    }

    #[test]
    fn a_denial_is_shared_as_joined() {
        let (gate, leader, follower) =
            leader_and_follower(vec![Decision::Deny, Decision::AllowOnce]);
        assert_eq!(leader.join().unwrap(), shown(Decision::Deny));
        assert_eq!(follower.join().unwrap(), joined(Decision::Deny));
        assert_eq!(gate.inner().inner.calls().len(), 1);
    }

    #[test]
    fn allow_once_is_never_shared_the_follower_prompts() {
        let (gate, leader, follower) =
            leader_and_follower(vec![Decision::AllowOnce, Decision::Deny]);
        assert_eq!(leader.join().unwrap(), shown(Decision::AllowOnce));
        // The follower now leads its own prompt.
        gate.inner().entered.wait();
        gate.inner().release.wait();
        assert_eq!(follower.join().unwrap(), shown(Decision::Deny));
        assert_eq!(gate.inner().inner.calls().len(), 2);
        assert!(lock(&gate.pending).is_empty());
    }

    #[test]
    fn after_allow_once_followers_prompt_one_at_a_time_in_order() {
        let gate = barrier_gate(
            vec![
                Decision::AllowOnce,
                Decision::AllowOnce,
                Decision::AllowFor(Duration::from_secs(900)),
            ],
            LONG,
        );
        let leader = spawn_approve(&gate);
        gate.inner().entered.wait();
        let first = spawn_approve(&gate);
        wait_for_waiter(&gate);
        let second = spawn_approve(&gate);
        let deadline = Instant::now() + Duration::from_secs(10);
        while gate.waiting("c", "k") < 2 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        gate.inner().release.wait();
        assert_eq!(leader.join().unwrap(), shown(Decision::AllowOnce));
        // Only one new prompt at a time: the oldest follower leads it.
        gate.inner().entered.wait();
        assert_eq!(gate.waiting("c", "k"), 1);
        gate.inner().release.wait();
        assert_eq!(first.join().unwrap(), shown(Decision::AllowOnce));
        gate.inner().entered.wait();
        gate.inner().release.wait();
        assert_eq!(
            second.join().unwrap(),
            shown(Decision::AllowFor(Duration::from_secs(900)))
        );
        assert_eq!(gate.inner().inner.calls().len(), 3);
    }

    #[test]
    fn a_follower_that_waits_too_long_is_denied() {
        let gate = barrier_gate(vec![Decision::AllowFor(LONG)], Duration::from_millis(100));
        let leader = spawn_approve(&gate);
        gate.inner().entered.wait();
        let start = Instant::now();
        let follower = spawn_approve(&gate).join().unwrap();
        assert_eq!(follower, joined(Decision::Deny));
        assert!(start.elapsed() >= Duration::from_millis(100));
        assert_eq!(gate.waiting("c", "k"), 0);
        gate.inner().release.wait();
        assert_eq!(leader.join().unwrap(), shown(Decision::AllowFor(LONG)));
        assert!(lock(&gate.pending).is_empty());
    }

    #[test]
    fn different_requests_or_clients_get_their_own_prompt() {
        let gate = PromptGate::new(
            ScriptedApprover::new(vec![
                Decision::AllowOnce,
                Decision::Deny,
                Decision::AllowOnce,
            ]),
            LONG,
        );
        assert_eq!(gate.approve("c", "k", &req()), shown(Decision::AllowOnce));
        // Not pending any more: a new identical request prompts again.
        assert_eq!(gate.approve("c", "k", &req()), shown(Decision::Deny));
        assert_eq!(gate.approve("d", "k", &req()), shown(Decision::AllowOnce));
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
        let gate = Arc::new(PromptGate::new(
            PanickingApprover {
                entered: Barrier::new(2),
                release: Barrier::new(2),
            },
            LONG,
        ));
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
        assert_eq!(follower.join().unwrap(), joined(Decision::Deny));
        assert!(lock(&gate.pending).is_empty());
    }

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn limits_from_env_only_tighten() {
        let base = Limits::mcp();
        assert_eq!(Limits::from_vars(base, vars(&[])), Ok(base));
        let stricter = Limits::from_vars(
            base,
            vars(&[
                ("ONEPASS_LIMIT_PROMPTS_PER_MIN", "2"),
                ("ONEPASS_LIMIT_SECRETS_PER_MIN", " 10 "),
                ("ONEPASS_LIMIT_DENIALS", "1"),
                ("ONEPASS_LIMIT_COOLDOWN_SECS", "3600"),
            ]),
        )
        .unwrap();
        assert_eq!(
            stricter,
            Limits {
                prompts_per_min: 2,
                secret_per_min: 10,
                denials_before_cooldown: 1,
                cooldown: Duration::from_secs(3600),
            }
        );
        // Looser values are clamped to the base.
        let looser = Limits::from_vars(
            Limits::ssh(),
            vars(&[
                ("ONEPASS_LIMIT_PROMPTS_PER_MIN", "600"),
                ("ONEPASS_LIMIT_SECRETS_PER_MIN", "99999999999"),
                ("ONEPASS_LIMIT_DENIALS", "50"),
                ("ONEPASS_LIMIT_COOLDOWN_SECS", "1"),
            ]),
        )
        .unwrap();
        assert_eq!(looser, Limits::ssh());
        // The cooldown is capped at 24 h.
        let long = Limits::from_vars(base, vars(&[("ONEPASS_LIMIT_COOLDOWN_SECS", "99999999")]));
        assert_eq!(long.unwrap().cooldown, Duration::from_secs(86_400));
    }

    #[test]
    fn limits_from_env_rejects_invalid_values() {
        for name in LIMIT_ENV_VARS {
            for bad in ["0", "-1", "abc", "", "1.5", "18446744073709551616"] {
                let err = Limits::from_vars(Limits::mcp(), vars(&[(name, bad)])).unwrap_err();
                assert!(err.contains(name), "{err}");
            }
        }
    }
}
