//! Agent hub: the in-process queue between the MCP tool `fill_in_browser`
//! and the browser extension (spec 5).
//!
//! The tool side calls [`AgentHub::probe`], asks the holder for consent,
//! then calls [`AgentHub::fill`]. Both block, outside the session lock,
//! until the extension answers or their timeout runs out. The extension
//! side is one listener per bridge session (one browser profile), made by
//! [`AgentHub::listener`]: it long-polls [`AgentHub::wait_job`] and answers
//! with [`AgentHub::probe_done`] and [`AgentHub::fill_done`].
//!
//! Routing: a probe is offered to one live listener at a time. The first
//! that finds the page owns the request; one that answers `tab_mismatch`
//! (not its focused tab) declines it and the probe goes to the next. The
//! probe fails with `tab_mismatch` only once every live listener declined.
//! The fill job, its answer and its ticket are bound to the owner: no other
//! browser can take the job, answer it or redeem the ticket.
//!
//! The bridge host calls [`AgentHub::redeem`] when the extension asks for
//! values with an agent context: each fill carries one ticket, good once,
//! for one item, one origin, one kind and its owner, for [`TICKET_TTL`].
//!
//! The hub holds ids, urls, origins, tab titles and field names only,
//! never a secret value.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How long the tool waits for the extension to answer a probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the tool waits for the extension to finish a fill.
pub const FILL_TIMEOUT: Duration = Duration::from_secs(30);
/// Lifetime of a fill ticket, by the hub clock.
pub const TICKET_TTL: Duration = Duration::from_secs(30);
/// Long-poll duration of one `agent_wait` request of the extension.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(25);
/// The extension counts as listening this long after its last poll.
pub const LISTENER_TTL: Duration = Duration::from_secs(30);
/// A probed request left without a fill (the tool gone without a word) is
/// closed after this long, so its client can probe again. It covers the
/// approval between probe and fill: the panel waits 60 s at most
/// (`DEFAULT_PROMPT_WAIT` of onepass-mcp), then Touch ID, with a wide
/// margin. A refused or failed approval cancels the request at once.
pub const REQUEST_TTL: Duration = Duration::from_secs(300);
/// Longest sleep of a waiting probe before it checks its listeners again
/// (a listener goes stale without waking anyone).
const RECHECK: Duration = Duration::from_millis(250);

/// Wall clock of the hub, in seconds. Injected so tests can move time.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// What an agent fill writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    Login,
    Card,
}

/// A job for the extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentJob {
    /// Report the active tab of the front window if it matches `url`.
    Probe { request_id: u64, url: String },
    /// Fill the probed document with `item_id`.
    Fill {
        request_id: u64,
        item_id: String,
        kind: AgentKind,
        submit: bool,
        document_id: String,
    },
}

/// The tab the extension found for a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub tab_title: String,
    pub origin: String,
    pub document_id: String,
}

/// What a fill wrote: field names, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillResult {
    pub filled: Vec<String>,
    pub submitted: bool,
}

/// Why a probe or a fill failed. Maps one to one onto the named tool
/// errors of spec 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentError {
    NoBrowser,
    Timeout,
    TabMismatch,
    OriginMismatch,
    CrossSiteFrame,
    NoFields,
    Denied,
}

/// One-shot right for the host to give the values of one item to the
/// extension, for one origin and one kind, on the owner's session only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTicket {
    pub request_id: u64,
    pub item_id: String,
    pub origin: String,
    pub kind: AgentKind,
    pub expires_at: u64,
    /// The listener that owns the request.
    pub owner: u64,
}

/// Where a request stands.
enum Phase {
    /// Probe offered in turn. `offered`: the listener holding it now;
    /// `declined`: those that said it is not their tab.
    Probing {
        url: String,
        offered: Option<u64>,
        declined: HashSet<u64>,
        mismatch: bool,
    },
    /// Probe answered by `owner`; waiting for consent and a fill.
    Probed { origin: String, at: u64, owner: u64 },
    /// Fill job for `owner`, queued (`job`) or taken, no answer yet.
    Filling { owner: u64, job: Option<AgentJob> },
}

struct Request {
    client: String,
    phase: Phase,
}

/// An answer of the extension, kept until its waiter takes it.
enum Answer {
    Probe(Result<ProbeResult, AgentError>),
    Fill(Result<FillResult, AgentError>),
}

/// One bridge session of the extension, by its polls.
#[derive(Default)]
struct Listener {
    last_poll: Option<u64>,
    waiting: usize,
}

#[derive(Default)]
struct State {
    next_id: u64,
    next_listener: u64,
    listeners: HashMap<u64, Listener>,
    /// By request id: the oldest request is offered first.
    requests: BTreeMap<u64, Request>,
    answers: HashMap<u64, Answer>,
    tickets: HashMap<u64, AgentTicket>,
}

impl State {
    /// Drops expired tickets and probed requests left without a fill.
    fn expire(&mut self, now: u64) {
        self.tickets.retain(|_, t| now < t.expires_at);
        let ttl = REQUEST_TTL.as_secs();
        self.requests.retain(|_, r| match r.phase {
            Phase::Probed { at, .. } => now < at.saturating_add(ttl),
            _ => true,
        });
    }

    fn client_busy(&self, client: &str) -> bool {
        self.requests.values().any(|r| r.client == client)
    }

    /// Ends a request: its job, answer and ticket go with it.
    fn close(&mut self, request_id: u64) {
        self.requests.remove(&request_id);
        self.answers.remove(&request_id);
        self.tickets.remove(&request_id);
    }

    /// A listener polling now, or within [`LISTENER_TTL`].
    fn live(&self, listener: u64, now: u64) -> bool {
        self.listeners.get(&listener).is_some_and(|l| {
            l.waiting > 0
                || l.last_poll
                    .is_some_and(|t| now.saturating_sub(t) <= LISTENER_TTL.as_secs())
        })
    }

    fn listening(&self, now: u64) -> bool {
        self.listeners.keys().any(|&l| self.live(l, now))
    }

    /// Frees the probes `listener` holds for the others (it is gone).
    fn drop_held(&mut self, listener: u64) {
        for request in self.requests.values_mut() {
            if let Phase::Probing {
                offered, declined, ..
            } = &mut request.phase
                && *offered == Some(listener)
            {
                declined.insert(listener);
                *offered = None;
            }
        }
    }

    /// The next job of `listener`: its own fill first, else the oldest
    /// probe it has not declined and nobody holds.
    fn take_job(&mut self, listener: u64) -> Option<AgentJob> {
        for request in self.requests.values_mut() {
            if let Phase::Filling { owner, job } = &mut request.phase
                && *owner == listener
                && let Some(job) = job.take()
            {
                return Some(job);
            }
        }
        for (&request_id, request) in self.requests.iter_mut() {
            if let Phase::Probing {
                url,
                offered,
                declined,
                ..
            } = &mut request.phase
                && offered.is_none()
                && !declined.contains(&listener)
            {
                *offered = Some(listener);
                return Some(AgentJob::Probe {
                    request_id,
                    url: url.clone(),
                });
            }
        }
        None
    }

    /// For a waiting probe: re-offers it when its holder went stale (`Ok(true)`),
    /// and gives its error once no live listener is left to ask
    /// (`tab_mismatch` when one declined it, else no browser).
    fn probe_settled(&mut self, request_id: u64, now: u64) -> Result<bool, AgentError> {
        let live: Vec<u64> = self
            .listeners
            .keys()
            .copied()
            .filter(|&l| self.live(l, now))
            .collect();
        let Some(Request {
            phase:
                Phase::Probing {
                    offered,
                    declined,
                    mismatch,
                    ..
                },
            ..
        }) = self.requests.get_mut(&request_id)
        else {
            return Ok(false);
        };
        let mut freed = false;
        if let Some(held) = *offered
            && !live.contains(&held)
        {
            declined.insert(held);
            *offered = None;
            freed = true;
        }
        if offered.is_none() && live.iter().all(|l| declined.contains(l)) {
            return Err(if *mismatch {
                AgentError::TabMismatch
            } else {
                AgentError::NoBrowser
            });
        }
        Ok(freed)
    }
}

fn deadline(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout)
        .unwrap_or_else(|| now + Duration::from_secs(86_400))
}

/// The queue between the tool and the extension. One `Mutex` over all
/// state and one `Condvar` woken on every change.
pub struct AgentHub {
    clock: Clock,
    state: Mutex<State>,
    changed: Condvar,
}

impl AgentHub {
    pub fn new(clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            clock,
            state: Mutex::new(State {
                next_id: 1,
                next_listener: 1,
                ..State::default()
            }),
            changed: Condvar::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits for a change until `until`, at most `slice` when given. `Err`
    /// (lock still held) once the deadline passed.
    fn wait<'a>(
        &self,
        guard: MutexGuard<'a, State>,
        until: Instant,
        slice: Option<Duration>,
    ) -> Result<MutexGuard<'a, State>, MutexGuard<'a, State>> {
        let now = Instant::now();
        if now >= until {
            return Err(guard);
        }
        let mut left = until - now;
        if let Some(s) = slice {
            left = left.min(s);
        }
        let (guard, _) = self
            .changed
            .wait_timeout(guard, left)
            .unwrap_or_else(|e| e.into_inner());
        Ok(guard)
    }

    /// A new listener id, for one bridge session. It counts as listening
    /// once it polls.
    pub fn register(&self) -> u64 {
        let mut state = self.lock();
        let id = state.next_listener;
        state.next_listener += 1;
        state.listeners.insert(id, Listener::default());
        id
    }

    /// The listener is gone (its session closed): a probe it held goes to
    /// the others, a fill it owns fails at once.
    pub fn unregister(&self, listener: u64) {
        let mut state = self.lock();
        state.listeners.remove(&listener);
        state.drop_held(listener);
        self.changed.notify_all();
    }

    /// A listener handle for one bridge session, unregistered when dropped.
    pub fn listener(self: &Arc<Self>) -> AgentListener {
        AgentListener {
            id: self.register(),
            hub: Arc::clone(self),
        }
    }

    /// Asks the extension for the active tab matching `url`. Returns the
    /// request id to carry into [`AgentHub::fill`]. One request per
    /// client at a time: a second probe waits for the first request to
    /// end, within its own `timeout`.
    pub fn probe(
        &self,
        client_id: &str,
        url: &str,
        timeout: Duration,
    ) -> Result<(u64, ProbeResult), AgentError> {
        let until = deadline(timeout);
        let mut state = self.lock();
        if !state.listening((self.clock)()) {
            return Err(AgentError::NoBrowser);
        }
        loop {
            state.expire((self.clock)());
            if !state.client_busy(client_id) {
                break;
            }
            state = match self.wait(state, until, None) {
                Ok(next) => next,
                Err(_) => return Err(AgentError::Timeout),
            };
        }
        let request_id = state.next_id;
        state.next_id += 1;
        state.requests.insert(
            request_id,
            Request {
                client: client_id.to_owned(),
                phase: Phase::Probing {
                    url: url.to_owned(),
                    offered: None,
                    declined: HashSet::new(),
                    mismatch: false,
                },
            },
        );
        self.changed.notify_all();
        loop {
            if let Some(Answer::Probe(result)) = state.answers.remove(&request_id) {
                match result {
                    Ok(page) => return Ok((request_id, page)),
                    Err(e) => {
                        state.close(request_id);
                        self.changed.notify_all();
                        return Err(e);
                    }
                }
            }
            match state.probe_settled(request_id, (self.clock)()) {
                Err(e) => {
                    state.close(request_id);
                    self.changed.notify_all();
                    return Err(e);
                }
                // Freed for another listener: wake the pollers.
                Ok(true) => self.changed.notify_all(),
                Ok(false) => {}
            }
            match self.wait(state, until, Some(RECHECK)) {
                Ok(next) => state = next,
                Err(mut state) => {
                    state.close(request_id);
                    self.changed.notify_all();
                    return Err(AgentError::Timeout);
                }
            }
        }
    }

    /// Fills the probed tab with `item_id`. `request_id` comes from
    /// [`AgentHub::probe`] of the same `client_id`, and `origin` must be the
    /// probed origin. Issues
    /// the ticket the host redeems, then queues the job for the listener
    /// that answered the probe, and for it only. The request ends with this
    /// call, whatever its outcome.
    #[allow(clippy::too_many_arguments)]
    pub fn fill(
        &self,
        client_id: &str,
        request_id: u64,
        item_id: &str,
        origin: &str,
        kind: AgentKind,
        submit: bool,
        document_id: &str,
        timeout: Duration,
    ) -> Result<FillResult, AgentError> {
        let until = deadline(timeout);
        let mut state = self.lock();
        let now = (self.clock)();
        state.expire(now);
        let (probed, owner) = match state.requests.get(&request_id) {
            Some(Request {
                client,
                phase: Phase::Probed { origin, owner, .. },
            }) if client == client_id => (origin.clone(), *owner),
            _ => return Err(AgentError::Timeout),
        };
        if probed != origin {
            state.close(request_id);
            self.changed.notify_all();
            return Err(AgentError::OriginMismatch);
        }
        if !state.listeners.contains_key(&owner) {
            state.close(request_id);
            self.changed.notify_all();
            return Err(AgentError::NoBrowser);
        }
        if let Some(request) = state.requests.get_mut(&request_id) {
            request.phase = Phase::Filling {
                owner,
                job: Some(AgentJob::Fill {
                    request_id,
                    item_id: item_id.to_owned(),
                    kind,
                    submit,
                    document_id: document_id.to_owned(),
                }),
            };
        }
        state.tickets.insert(
            request_id,
            AgentTicket {
                request_id,
                item_id: item_id.to_owned(),
                origin: origin.to_owned(),
                kind,
                expires_at: now.saturating_add(TICKET_TTL.as_secs()),
                owner,
            },
        );
        self.changed.notify_all();
        loop {
            if let Some(Answer::Fill(result)) = state.answers.remove(&request_id) {
                state.close(request_id);
                self.changed.notify_all();
                return result;
            }
            // The owner's session closed: no one else may fill.
            if !state.listeners.contains_key(&owner) {
                state.close(request_id);
                self.changed.notify_all();
                return Err(AgentError::NoBrowser);
            }
            match self.wait(state, until, None) {
                Ok(next) => state = next,
                Err(mut state) => {
                    state.close(request_id);
                    self.changed.notify_all();
                    return Err(AgentError::Timeout);
                }
            }
        }
    }

    /// Ends a probed request the tool will not fill (consent refused),
    /// so its client can probe again at once.
    pub fn cancel(&self, request_id: u64) {
        let mut state = self.lock();
        if matches!(
            state.requests.get(&request_id).map(|r| &r.phase),
            Some(Phase::Probed { .. })
        ) {
            state.close(request_id);
            self.changed.notify_all();
        }
    }

    /// Extension side: `listener` takes its next job, waiting up to
    /// `timeout`. Only the hub's own lock is held, through the condvar.
    pub fn wait_job(&self, listener: u64, timeout: Duration) -> Option<AgentJob> {
        let until = deadline(timeout);
        let mut state = self.lock();
        let now = (self.clock)();
        {
            let l = state.listeners.entry(listener).or_default();
            l.waiting += 1;
            l.last_poll = Some(now);
        }
        // Being live may change a waiting probe.
        self.changed.notify_all();
        let job = loop {
            if let Some(job) = state.take_job(listener) {
                break Some(job);
            }
            match self.wait(state, until, None) {
                Ok(next) => state = next,
                Err(last) => {
                    state = last;
                    break None;
                }
            }
        };
        let now = (self.clock)();
        if let Some(l) = state.listeners.get_mut(&listener) {
            l.waiting = l.waiting.saturating_sub(1);
            l.last_poll = Some(now);
        }
        self.changed.notify_all();
        job
    }

    /// Extension side: `listener` answers a probe it was offered. Dropped
    /// unless that probe is still waiting on this listener. A page found
    /// makes the listener the owner; `tab_mismatch` or a refusal declines
    /// the probe, which goes to the next live listener.
    pub fn probe_done(
        &self,
        listener: u64,
        request_id: u64,
        result: Result<ProbeResult, AgentError>,
    ) {
        let mut guard = self.lock();
        let state = &mut *guard;
        if state.answers.contains_key(&request_id) {
            return;
        }
        let now = (self.clock)();
        let Some(request) = state.requests.get_mut(&request_id) else {
            return;
        };
        let Phase::Probing {
            offered,
            declined,
            mismatch,
            ..
        } = &mut request.phase
        else {
            return;
        };
        if *offered != Some(listener) {
            return;
        }
        match result {
            Ok(page) => {
                request.phase = Phase::Probed {
                    origin: page.origin.clone(),
                    at: now,
                    owner: listener,
                };
                state.answers.insert(request_id, Answer::Probe(Ok(page)));
            }
            Err(e @ (AgentError::TabMismatch | AgentError::Denied)) => {
                if e == AgentError::TabMismatch {
                    *mismatch = true;
                }
                declined.insert(listener);
                *offered = None;
            }
            Err(e) => {
                state.answers.insert(request_id, Answer::Probe(Err(e)));
            }
        }
        self.changed.notify_all();
    }

    /// Extension side: `listener` answers a fill. Dropped unless that fill
    /// is still waiting and `listener` owns it.
    pub fn fill_done(
        &self,
        listener: u64,
        request_id: u64,
        result: Result<FillResult, AgentError>,
    ) {
        let mut state = self.lock();
        let waiting = matches!(
            state.requests.get(&request_id).map(|r| &r.phase),
            Some(Phase::Filling { owner, .. }) if *owner == listener
        );
        if waiting && !state.answers.contains_key(&request_id) {
            state.answers.insert(request_id, Answer::Fill(result));
            self.changed.notify_all();
        }
    }

    /// True while the extension polls: some listener's `wait_job` is
    /// blocked now or returned within [`LISTENER_TTL`].
    pub fn has_listener(&self) -> bool {
        self.lock().listening((self.clock)())
    }

    /// Host side: true while `request_id` holds an unexpired ticket owned
    /// by `listener`. Does not spend it (`plan_fill` asks before the values
    /// are asked for).
    pub fn ticket_live(&self, listener: u64, request_id: u64) -> bool {
        let mut state = self.lock();
        state.expire((self.clock)());
        state
            .tickets
            .get(&request_id)
            .is_some_and(|t| t.owner == listener)
    }

    /// Inspection only: whether `request_id` holds an unexpired ticket,
    /// whoever owns it. Never opens values.
    pub fn ticket_held(&self, request_id: u64) -> bool {
        let mut state = self.lock();
        state.expire((self.clock)());
        state.tickets.contains_key(&request_id)
    }

    /// Host side: spends the ticket of `request_id` if `listener` owns it,
    /// item, origin (exact string) and kind match and it has not expired.
    /// True once at most. A mismatch leaves the ticket in place.
    pub fn redeem(
        &self,
        listener: u64,
        request_id: u64,
        item_id: &str,
        origin: &str,
        kind: AgentKind,
    ) -> bool {
        let mut state = self.lock();
        state.expire((self.clock)());
        let good = state.tickets.get(&request_id).is_some_and(|t| {
            t.owner == listener && t.item_id == item_id && t.origin == origin && t.kind == kind
        });
        if good {
            state.tickets.remove(&request_id);
        }
        good
    }
}

/// The hub as one bridge session sees it: every extension-side call goes
/// with this session's listener id. Unregisters on drop.
pub struct AgentListener {
    hub: Arc<AgentHub>,
    id: u64,
}

impl AgentListener {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn hub(&self) -> &Arc<AgentHub> {
        &self.hub
    }

    pub fn wait_job(&self, timeout: Duration) -> Option<AgentJob> {
        self.hub.wait_job(self.id, timeout)
    }

    pub fn probe_done(&self, request_id: u64, result: Result<ProbeResult, AgentError>) {
        self.hub.probe_done(self.id, request_id, result);
    }

    pub fn fill_done(&self, request_id: u64, result: Result<FillResult, AgentError>) {
        self.hub.fill_done(self.id, request_id, result);
    }

    pub fn ticket_live(&self, request_id: u64) -> bool {
        self.hub.ticket_live(self.id, request_id)
    }

    pub fn redeem(&self, request_id: u64, item_id: &str, origin: &str, kind: AgentKind) -> bool {
        self.hub.redeem(self.id, request_id, item_id, origin, kind)
    }
}

impl Drop for AgentListener {
    fn drop(&mut self) {
        self.hub.unregister(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    const SHORT: Duration = Duration::from_millis(100);
    const LONG: Duration = Duration::from_secs(5);

    fn hub() -> (Arc<AgentHub>, Arc<AtomicU64>) {
        let now = Arc::new(AtomicU64::new(1_000));
        let tick = Arc::clone(&now);
        let hub = AgentHub::new(Arc::new(move || tick.load(Ordering::SeqCst)));
        (hub, now)
    }

    /// A new listener of the extension, marked as listening without
    /// taking a job.
    fn listen(hub: &AgentHub) -> u64 {
        let l = hub.register();
        assert!(hub.wait_job(l, Duration::ZERO).is_none());
        l
    }

    fn page(title: &str) -> ProbeResult {
        ProbeResult {
            tab_title: title.to_owned(),
            origin: "https://github.com".to_owned(),
            document_id: format!("doc-{title}"),
        }
    }

    /// Simulated extension: answers every probe with `page(title)`, where
    /// the title is the probed url, and every fill with the given fields
    /// after redeeming its ticket.
    fn extension(hub: Arc<AgentHub>, l: u64, jobs: usize) -> thread::JoinHandle<Vec<bool>> {
        thread::spawn(move || {
            let mut redeemed = Vec::new();
            for _ in 0..jobs {
                match hub.wait_job(l, LONG) {
                    Some(AgentJob::Probe { request_id, url }) => {
                        hub.probe_done(l, request_id, Ok(page(&url)));
                    }
                    Some(AgentJob::Fill {
                        request_id,
                        item_id,
                        kind,
                        submit,
                        ..
                    }) => {
                        redeemed.push(hub.redeem(
                            l,
                            request_id,
                            &item_id,
                            "https://github.com",
                            kind,
                        ));
                        hub.fill_done(
                            l,
                            request_id,
                            Ok(FillResult {
                                filled: vec!["username".to_owned(), "password".to_owned()],
                                submitted: submit,
                            }),
                        );
                    }
                    None => break,
                }
            }
            redeemed
        })
    }

    #[test]
    fn constants_match_the_spec() {
        assert_eq!(PROBE_TIMEOUT, Duration::from_secs(10));
        assert_eq!(FILL_TIMEOUT, Duration::from_secs(30));
        assert_eq!(TICKET_TTL, Duration::from_secs(30));
        assert_eq!(WAIT_TIMEOUT, Duration::from_secs(25));
    }

    #[test]
    fn probe_without_listener_is_no_browser() {
        let (hub, _) = hub();
        assert!(!hub.has_listener());
        let started = std::time::Instant::now();
        let out = hub.probe("claude", "https://github.com/login", LONG);
        assert_eq!(out.unwrap_err(), AgentError::NoBrowser);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn listener_goes_stale_after_30s() {
        let (hub, now) = hub();
        listen(&hub);
        assert!(hub.has_listener());
        now.fetch_add(30, Ordering::SeqCst);
        assert!(hub.has_listener());
        now.fetch_add(1, Ordering::SeqCst);
        assert!(!hub.has_listener());
        let out = hub.probe("claude", "https://github.com/login", LONG);
        assert_eq!(out.unwrap_err(), AgentError::NoBrowser);
    }

    #[test]
    fn probe_times_out_after_10s_when_extension_never_answers() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let out = hub.probe("claude", "https://github.com/login", SHORT);
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        // The unanswered job does not linger for a later listener.
        assert!(hub.wait_job(l, Duration::ZERO).is_none());
        // The client is free again.
        let ext = extension(Arc::clone(&hub), l, 1);
        let (_, got) = hub.probe("claude", "https://github.com/x", LONG).unwrap();
        assert_eq!(got.tab_title, "https://github.com/x");
        ext.join().unwrap();
    }

    #[test]
    fn probe_returns_the_extension_result() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, got) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        assert!(id > 0);
        assert_eq!(got, page("https://github.com/login"));
        ext.join().unwrap();
    }

    #[test]
    fn probe_passes_the_extension_error_through() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || {
            if let Some(AgentJob::Probe { request_id, .. }) = h.wait_job(l, LONG) {
                h.probe_done(l, request_id, Err(AgentError::TabMismatch));
            }
        });
        let out = hub.probe("claude", "https://github.com/login", LONG);
        assert_eq!(out.unwrap_err(), AgentError::TabMismatch);
        ext.join().unwrap();
    }

    #[test]
    fn fill_issues_a_ticket_redeemable_once() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 2);
        let (id, page) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        let out = hub
            .fill(
                "claude",
                id,
                "item-1",
                &page.origin,
                AgentKind::Login,
                true,
                &page.document_id,
                LONG,
            )
            .unwrap();
        assert_eq!(out.filled, vec!["username", "password"]);
        assert!(out.submitted);
        // First redeem (inside the extension) succeeded.
        assert_eq!(ext.join().unwrap(), vec![true]);
        // A second redeem of the same ticket fails.
        assert!(!hub.redeem(l, id, "item-1", "https://github.com", AgentKind::Login));
    }

    #[test]
    fn fill_job_carries_the_probe_document() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, page) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let h = Arc::clone(&hub);
        let filler = thread::spawn(move || {
            h.fill(
                "claude",
                id,
                "item-1",
                "https://github.com",
                AgentKind::Card,
                false,
                "doc-9",
                LONG,
            )
        });
        let job = hub.wait_job(l, LONG).unwrap();
        assert_eq!(
            job,
            AgentJob::Fill {
                request_id: id,
                item_id: "item-1".to_owned(),
                kind: AgentKind::Card,
                submit: false,
                document_id: "doc-9".to_owned(),
            }
        );
        assert!(hub.redeem(l, id, "item-1", "https://github.com", AgentKind::Card));
        hub.fill_done(l, id, Err(AgentError::NoFields));
        assert_eq!(filler.join().unwrap().unwrap_err(), AgentError::NoFields);
        let _ = page;
    }

    #[test]
    fn ticket_refused_for_other_item_or_origin() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, page) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let h = Arc::clone(&hub);
        let origin = page.origin.clone();
        let filler = thread::spawn(move || {
            h.fill(
                "claude",
                id,
                "item-1",
                &origin,
                AgentKind::Login,
                false,
                "doc",
                LONG,
            )
        });
        let Some(AgentJob::Fill { request_id, .. }) = hub.wait_job(l, LONG) else {
            panic!("expected a fill job");
        };
        assert_eq!(request_id, id);
        assert!(!hub.redeem(l, id, "item-2", "https://github.com", AgentKind::Login));
        assert!(!hub.redeem(l, id, "item-1", "https://evil.example", AgentKind::Login));
        assert!(!hub.redeem(l, id, "item-1", "https://gist.github.com", AgentKind::Login));
        assert!(!hub.redeem(l, id, "item-1", "https://github.com", AgentKind::Card));
        assert!(!hub.redeem(l, id + 1, "item-1", "https://github.com", AgentKind::Login));
        // Wrong guesses do not burn the ticket.
        assert!(hub.redeem(l, id, "item-1", "https://github.com", AgentKind::Login));
        hub.fill_done(
            l,
            id,
            Ok(FillResult {
                filled: vec!["password".to_owned()],
                submitted: false,
            }),
        );
        assert_eq!(filler.join().unwrap().unwrap().filled, vec!["password"]);
    }

    #[test]
    fn ticket_live_does_not_spend_the_ticket() {
        let (hub, now) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        // Probed, no fill yet: no ticket.
        assert!(!hub.ticket_live(l, id));
        let h = Arc::clone(&hub);
        let filler = thread::spawn(move || {
            h.fill(
                "claude",
                id,
                "item-1",
                "https://github.com",
                AgentKind::Login,
                false,
                "doc",
                LONG,
            )
        });
        let Some(AgentJob::Fill { .. }) = hub.wait_job(l, LONG) else {
            panic!("expected a fill job");
        };
        assert!(hub.ticket_live(l, id));
        assert!(hub.ticket_live(l, id));
        assert!(!hub.ticket_live(l, id + 1));
        assert!(hub.redeem(l, id, "item-1", "https://github.com", AgentKind::Login));
        assert!(!hub.ticket_live(l, id));
        hub.fill_done(l, id, Err(AgentError::Denied));
        assert_eq!(filler.join().unwrap().unwrap_err(), AgentError::Denied);

        // An unspent ticket dies with its TTL.
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let h = Arc::clone(&hub);
        let filler = thread::spawn(move || {
            h.fill(
                "claude",
                id,
                "item-1",
                "https://github.com",
                AgentKind::Login,
                false,
                "doc",
                LONG,
            )
        });
        let Some(AgentJob::Fill { .. }) = hub.wait_job(l, LONG) else {
            panic!("expected a fill job");
        };
        assert!(hub.ticket_live(l, id));
        now.fetch_add(31, Ordering::SeqCst);
        assert!(!hub.ticket_live(l, id));
        hub.fill_done(l, id, Err(AgentError::Denied));
        filler.join().unwrap().unwrap_err();
    }

    #[test]
    fn ticket_refused_after_30s() {
        let (hub, now) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let h = Arc::clone(&hub);
        let filler = thread::spawn(move || {
            h.fill(
                "claude",
                id,
                "item-1",
                "https://github.com",
                AgentKind::Login,
                false,
                "doc",
                LONG,
            )
        });
        let Some(AgentJob::Fill { .. }) = hub.wait_job(l, LONG) else {
            panic!("expected a fill job");
        };
        now.fetch_add(31, Ordering::SeqCst);
        assert!(!hub.redeem(l, id, "item-1", "https://github.com", AgentKind::Login));
        hub.fill_done(l, id, Err(AgentError::Denied));
        assert_eq!(filler.join().unwrap().unwrap_err(), AgentError::Denied);
    }

    #[test]
    fn fill_refused_for_unknown_request_or_other_origin() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let out = hub.fill(
            "claude",
            42,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "d",
            SHORT,
        );
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let out = hub.fill(
            "claude",
            id,
            "item-1",
            "https://gitlab.com",
            AgentKind::Login,
            false,
            "d",
            SHORT,
        );
        assert_eq!(out.unwrap_err(), AgentError::OriginMismatch);
        // No job and no ticket were made for the refused fill.
        assert!(hub.wait_job(l, Duration::ZERO).is_none());
        assert!(!hub.redeem(l, id, "item-1", "https://gitlab.com", AgentKind::Login));
        assert!(!hub.redeem(l, id, "item-1", "https://github.com", AgentKind::Login));
    }

    #[test]
    fn fill_times_out_and_its_ticket_dies() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let out = hub.fill(
            "claude",
            id,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "d",
            SHORT,
        );
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        assert!(hub.wait_job(l, Duration::ZERO).is_none());
        assert!(!hub.redeem(l, id, "item-1", "https://github.com", AgentKind::Login));
        // Fill cannot be retried on a finished request.
        let out = hub.fill(
            "claude",
            id,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "d",
            SHORT,
        );
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
    }

    #[test]
    fn two_clients_never_receive_each_others_results() {
        let (hub, _) = hub();
        let l = listen(&hub);
        // The extension answers the two probes in reverse order.
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || {
            let mut seen = Vec::new();
            while seen.len() < 2 {
                if let Some(AgentJob::Probe { request_id, url }) = h.wait_job(l, LONG) {
                    seen.push((request_id, url));
                }
            }
            for (request_id, url) in seen.into_iter().rev() {
                h.probe_done(l, request_id, Ok(page(&url)));
            }
        });
        let a = Arc::clone(&hub);
        let ta = thread::spawn(move || a.probe("agent-a", "https://github.com/a", LONG));
        let b = Arc::clone(&hub);
        let tb = thread::spawn(move || b.probe("agent-b", "https://github.com/b", LONG));
        let (ida, ra) = ta.join().unwrap().unwrap();
        let (idb, rb) = tb.join().unwrap().unwrap();
        ext.join().unwrap();
        assert_ne!(ida, idb);
        assert_eq!(ra.tab_title, "https://github.com/a");
        assert_eq!(rb.tab_title, "https://github.com/b");
    }

    #[test]
    fn second_probe_of_a_client_waits_for_the_first_request() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        // The first request is still open (waiting for fill): the second
        // probe of the same client times out without reaching the extension.
        let out = hub.probe("claude", "https://github.com/other", SHORT);
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        assert!(hub.wait_job(l, Duration::ZERO).is_none());
        // Another client is not blocked.
        let ext = extension(Arc::clone(&hub), l, 1);
        assert!(hub.probe("other", "https://github.com/x", LONG).is_ok());
        ext.join().unwrap();
        // Once the first request finishes, the queued probe goes through.
        let h = Arc::clone(&hub);
        let second = thread::spawn(move || h.probe("claude", "https://github.com/next", LONG));
        thread::sleep(SHORT);
        let ext = extension(Arc::clone(&hub), l, 2);
        let done = hub.fill(
            "claude",
            id,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "d",
            LONG,
        );
        assert!(done.is_ok());
        let (id2, got) = second.join().unwrap().unwrap();
        assert!(id2 > id);
        assert_eq!(got.tab_title, "https://github.com/next");
        assert_eq!(ext.join().unwrap(), vec![true]);
    }

    #[test]
    fn late_answer_for_a_timed_out_request_is_dropped() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || match h.wait_job(l, LONG) {
            Some(AgentJob::Probe { request_id, .. }) => request_id,
            _ => panic!("expected a probe"),
        });
        let out = hub.probe("claude", "https://github.com/late", SHORT);
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        let stale = ext.join().unwrap();
        // The answer arrives after the timeout.
        hub.probe_done(l, stale, Ok(page("stale")));
        hub.fill_done(
            l,
            stale,
            Ok(FillResult {
                filled: vec!["password".to_owned()],
                submitted: false,
            }),
        );
        // The next request of the same client gets its own answer only.
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || match h.wait_job(l, LONG) {
            Some(AgentJob::Probe { request_id, url }) => {
                h.probe_done(l, stale, Ok(page("stale again")));
                h.probe_done(l, request_id, Ok(page(&url)));
                request_id
            }
            _ => panic!("expected a probe"),
        });
        let (id, got) = hub
            .probe("claude", "https://github.com/fresh", LONG)
            .unwrap();
        assert_eq!(ext.join().unwrap(), id);
        assert_ne!(id, stale);
        assert_eq!(got.tab_title, "https://github.com/fresh");
        // A fill on the stale request is refused.
        let out = hub.fill(
            "claude",
            stale,
            "i",
            "https://github.com",
            AgentKind::Login,
            false,
            "d",
            SHORT,
        );
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
    }

    #[test]
    fn answer_of_the_wrong_kind_is_dropped() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || {
            if let Some(AgentJob::Probe { request_id, .. }) = h.wait_job(l, LONG) {
                h.fill_done(
                    l,
                    request_id,
                    Ok(FillResult {
                        filled: vec![],
                        submitted: false,
                    }),
                );
            }
        });
        let out = hub.probe("claude", "https://github.com/login", SHORT);
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        ext.join().unwrap();
    }

    // ---- routing between several listeners (two browsers or profiles)

    #[test]
    fn probe_declined_by_one_listener_goes_to_the_other() {
        let (hub, _) = hub();
        let a = listen(&hub);
        let b = listen(&hub);
        let ha = Arc::clone(&hub);
        // Browser A takes the probe first and says it is not its tab.
        let first = thread::spawn(move || match ha.wait_job(a, LONG) {
            Some(AgentJob::Probe { request_id, .. }) => {
                ha.probe_done(a, request_id, Err(AgentError::TabMismatch));
                // A polls again: the declined probe is never offered back.
                assert!(ha.wait_job(a, SHORT).is_none());
                request_id
            }
            other => panic!("expected a probe, got {other:?}"),
        });
        let tool = Arc::clone(&hub);
        let prober = thread::spawn(move || tool.probe("claude", "https://github.com/login", LONG));
        let declined = first.join().unwrap();
        // Browser B gets it and finds the page.
        let Some(AgentJob::Probe { request_id, url }) = hub.wait_job(b, LONG) else {
            panic!("expected the re-offered probe");
        };
        assert_eq!(request_id, declined);
        hub.probe_done(b, request_id, Ok(page(&url)));
        let (id, got) = prober.join().unwrap().unwrap();
        assert_eq!(id, request_id);
        assert_eq!(got.tab_title, "https://github.com/login");

        // The fill is bound to B: A never sees it, nor its ticket.
        let tool = Arc::clone(&hub);
        let filler = thread::spawn(move || {
            tool.fill(
                "claude",
                id,
                "item-1",
                "https://github.com",
                AgentKind::Login,
                false,
                "doc",
                LONG,
            )
        });
        let ha = Arc::clone(&hub);
        let a_poll = thread::spawn(move || ha.wait_job(a, Duration::from_millis(300)));
        let job = hub.wait_job(b, LONG).unwrap();
        assert!(matches!(job, AgentJob::Fill { request_id, .. } if request_id == id));
        assert_eq!(a_poll.join().unwrap(), None);
        assert!(!hub.ticket_live(a, id));
        assert!(!hub.redeem(a, id, "item-1", "https://github.com", AgentKind::Login));
        // A's answer to B's fill is dropped.
        hub.fill_done(
            a,
            id,
            Ok(FillResult {
                filled: vec!["password".to_owned()],
                submitted: true,
            }),
        );
        assert!(hub.ticket_live(b, id));
        assert!(hub.redeem(b, id, "item-1", "https://github.com", AgentKind::Login));
        hub.fill_done(
            b,
            id,
            Ok(FillResult {
                filled: vec!["username".to_owned()],
                submitted: false,
            }),
        );
        let out = filler.join().unwrap().unwrap();
        assert_eq!(out.filled, vec!["username"]);
        assert!(!out.submitted);
    }

    #[test]
    fn probe_is_tab_mismatch_once_every_live_listener_declined() {
        let (hub, now) = hub();
        let a = listen(&hub);
        let b = listen(&hub);
        let stale = listen(&hub);
        // `stale` stopped polling long ago: it is not waited for.
        now.fetch_add(20, Ordering::SeqCst);
        assert!(hub.wait_job(a, Duration::ZERO).is_none());
        assert!(hub.wait_job(b, Duration::ZERO).is_none());
        now.fetch_add(15, Ordering::SeqCst);
        let _ = stale;
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || {
            for l in [a, b] {
                match h.wait_job(l, LONG) {
                    Some(AgentJob::Probe { request_id, .. }) => {
                        h.probe_done(l, request_id, Err(AgentError::TabMismatch));
                    }
                    other => panic!("expected a probe, got {other:?}"),
                }
            }
        });
        let started = std::time::Instant::now();
        let out = hub.probe("claude", "https://github.com/login", LONG);
        assert_eq!(out.unwrap_err(), AgentError::TabMismatch);
        assert!(started.elapsed() < Duration::from_secs(2));
        ext.join().unwrap();
        // The request is closed: the client probes again at once.
        assert!(hub.wait_job(a, Duration::ZERO).is_none());
    }

    #[test]
    fn probe_offer_moves_on_when_its_holder_leaves() {
        let (hub, _) = hub();
        let gone = hub.listener();
        assert!(gone.wait_job(Duration::ZERO).is_none());
        let b = listen(&hub);
        let tool = Arc::clone(&hub);
        let prober = thread::spawn(move || tool.probe("claude", "https://github.com/login", LONG));
        // The leaving session takes the probe, then closes without a word.
        let Some(AgentJob::Probe { request_id, .. }) = gone.wait_job(LONG) else {
            panic!("expected a probe");
        };
        drop(gone);
        let Some(AgentJob::Probe {
            request_id: again,
            url,
        }) = hub.wait_job(b, LONG)
        else {
            panic!("expected the probe again");
        };
        assert_eq!(again, request_id);
        hub.probe_done(b, again, Ok(page(&url)));
        assert!(prober.join().unwrap().is_ok());
    }

    #[test]
    fn fill_fails_at_once_when_its_owner_leaves() {
        let (hub, _) = hub();
        let owner = hub.listener();
        assert!(owner.wait_job(Duration::ZERO).is_none());
        let other = listen(&hub);
        let tool = Arc::clone(&hub);
        let prober = thread::spawn(move || tool.probe("claude", "https://github.com/login", LONG));
        let Some(AgentJob::Probe { request_id, url }) = owner.wait_job(LONG) else {
            panic!("expected a probe");
        };
        owner.probe_done(request_id, Ok(page(&url)));
        let (id, _) = prober.join().unwrap().unwrap();
        drop(owner);
        let started = std::time::Instant::now();
        let out = hub.fill(
            "claude",
            id,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "doc",
            LONG,
        );
        assert_eq!(out.unwrap_err(), AgentError::NoBrowser);
        assert!(started.elapsed() < Duration::from_secs(1));
        // Nothing was queued for the other browser.
        assert!(hub.wait_job(other, Duration::ZERO).is_none());
    }

    #[test]
    fn probe_answer_from_a_listener_not_offered_is_dropped() {
        let (hub, _) = hub();
        let a = listen(&hub);
        let b = listen(&hub);
        let tool = Arc::clone(&hub);
        let prober = thread::spawn(move || tool.probe("claude", "https://github.com/login", SHORT));
        let Some(AgentJob::Probe { request_id, .. }) = hub.wait_job(a, LONG) else {
            panic!("expected a probe");
        };
        // B was never offered this probe: its page, or its decline, counts
        // for nothing.
        hub.probe_done(b, request_id, Ok(page("forged")));
        hub.probe_done(b, request_id, Err(AgentError::TabMismatch));
        assert_eq!(prober.join().unwrap().unwrap_err(), AgentError::Timeout);
    }

    #[test]
    fn request_lives_through_a_slow_approval() {
        let (hub, now) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        // The panel waits 60 s, then Touch ID: the request is still there.
        now.fetch_add(200, Ordering::SeqCst);
        assert!(hub.wait_job(l, Duration::ZERO).is_none());
        let ext = extension(Arc::clone(&hub), l, 1);
        let out = hub.fill(
            "claude",
            id,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "doc",
            LONG,
        );
        assert!(out.is_ok(), "{out:?}");
        assert_eq!(ext.join().unwrap(), vec![true]);
        assert!(REQUEST_TTL >= Duration::from_secs(60) + Duration::from_secs(120));
    }

    #[test]
    fn fill_of_another_clients_request_is_refused() {
        let (hub, _) = hub();
        let l = listen(&hub);
        let ext = extension(Arc::clone(&hub), l, 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let out = hub.fill(
            "other-agent",
            id,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "doc",
            SHORT,
        );
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        // Nothing was queued nor ticketed; the owner client still fills.
        assert!(hub.wait_job(l, Duration::ZERO).is_none());
        assert!(!hub.ticket_held(id));
        let ext = extension(Arc::clone(&hub), l, 1);
        let out = hub.fill(
            "claude",
            id,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "doc",
            LONG,
        );
        assert!(out.is_ok());
        assert_eq!(ext.join().unwrap(), vec![true]);
    }
}
