//! Agent hub: the in-process queue between the MCP tool `fill_in_browser`
//! and the browser extension (spec 5).
//!
//! The tool side calls [`AgentHub::probe`], asks the holder for consent,
//! then calls [`AgentHub::fill`]. Both block, outside the session lock,
//! until the extension answers or their timeout runs out. The extension
//! side long-polls [`AgentHub::wait_job`] and answers with
//! [`AgentHub::probe_done`] and [`AgentHub::fill_done`]. The bridge host
//! calls [`AgentHub::redeem`] when the extension asks for values with an
//! agent context: each fill carries one ticket, good once, for one item,
//! one origin and one kind, for [`TICKET_TTL`].
//!
//! The hub holds ids, urls, origins, tab titles and field names only,
//! never a secret value.

use std::collections::{HashMap, VecDeque};
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
/// A probed request left without a fill (consent refused, tool gone) is
/// closed after this long, so its client can probe again.
pub const REQUEST_TTL: Duration = Duration::from_secs(120);

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
/// extension, for one origin and one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTicket {
    pub request_id: u64,
    pub item_id: String,
    pub origin: String,
    pub kind: AgentKind,
    pub expires_at: u64,
}

/// Where a request stands.
enum Phase {
    /// Probe job queued or taken, no answer yet.
    Probing,
    /// Probe answered; waiting for consent and a fill.
    Probed { origin: String, at: u64 },
    /// Fill job queued or taken, no answer yet.
    Filling,
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

#[derive(Default)]
struct State {
    next_id: u64,
    jobs: VecDeque<AgentJob>,
    requests: HashMap<u64, Request>,
    answers: HashMap<u64, Answer>,
    tickets: HashMap<u64, AgentTicket>,
    last_wait: Option<u64>,
    waiters: usize,
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

    /// Ends a request: its queued job, answer and ticket go with it.
    fn close(&mut self, request_id: u64) {
        self.requests.remove(&request_id);
        self.answers.remove(&request_id);
        self.tickets.remove(&request_id);
        self.jobs.retain(|job| job_id(job) != request_id);
    }

    fn listening(&self, now: u64) -> bool {
        self.waiters > 0
            || self
                .last_wait
                .is_some_and(|t| now.saturating_sub(t) <= LISTENER_TTL.as_secs())
    }
}

fn job_id(job: &AgentJob) -> u64 {
    match job {
        AgentJob::Probe { request_id, .. } | AgentJob::Fill { request_id, .. } => *request_id,
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
                ..State::default()
            }),
            changed: Condvar::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits for a change until `until`. `Err` (lock still held) once the
    /// deadline passed.
    fn wait<'a>(
        &self,
        guard: MutexGuard<'a, State>,
        until: Instant,
    ) -> Result<MutexGuard<'a, State>, MutexGuard<'a, State>> {
        let now = Instant::now();
        if now >= until {
            return Err(guard);
        }
        let (guard, _) = self
            .changed
            .wait_timeout(guard, until - now)
            .unwrap_or_else(|e| e.into_inner());
        Ok(guard)
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
            state = match self.wait(state, until) {
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
                phase: Phase::Probing,
            },
        );
        state.jobs.push_back(AgentJob::Probe {
            request_id,
            url: url.to_owned(),
        });
        self.changed.notify_all();
        loop {
            if let Some(Answer::Probe(result)) = state.answers.remove(&request_id) {
                match result {
                    Ok(page) => {
                        if let Some(request) = state.requests.get_mut(&request_id) {
                            request.phase = Phase::Probed {
                                origin: page.origin.clone(),
                                at: (self.clock)(),
                            };
                        }
                        return Ok((request_id, page));
                    }
                    Err(e) => {
                        state.close(request_id);
                        self.changed.notify_all();
                        return Err(e);
                    }
                }
            }
            match self.wait(state, until) {
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
    /// [`AgentHub::probe`] and `origin` must be the probed origin. Issues
    /// the ticket the host redeems, then queues the job. The request ends
    /// with this call, whatever its outcome.
    #[allow(clippy::too_many_arguments)]
    pub fn fill(
        &self,
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
        let probed = match state.requests.get(&request_id).map(|r| &r.phase) {
            Some(Phase::Probed { origin, .. }) => origin.clone(),
            _ => return Err(AgentError::Timeout),
        };
        if probed != origin {
            state.close(request_id);
            self.changed.notify_all();
            return Err(AgentError::OriginMismatch);
        }
        if let Some(request) = state.requests.get_mut(&request_id) {
            request.phase = Phase::Filling;
        }
        state.tickets.insert(
            request_id,
            AgentTicket {
                request_id,
                item_id: item_id.to_owned(),
                origin: origin.to_owned(),
                kind,
                expires_at: now.saturating_add(TICKET_TTL.as_secs()),
            },
        );
        state.jobs.push_back(AgentJob::Fill {
            request_id,
            item_id: item_id.to_owned(),
            kind,
            submit,
            document_id: document_id.to_owned(),
        });
        self.changed.notify_all();
        loop {
            if let Some(Answer::Fill(result)) = state.answers.remove(&request_id) {
                state.close(request_id);
                self.changed.notify_all();
                return result;
            }
            match self.wait(state, until) {
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

    /// Extension side: takes the next job, waiting up to `timeout`.
    pub fn wait_job(&self, timeout: Duration) -> Option<AgentJob> {
        let until = deadline(timeout);
        let mut state = self.lock();
        state.waiters += 1;
        state.last_wait = Some((self.clock)());
        let job = loop {
            if let Some(job) = state.jobs.pop_front() {
                break Some(job);
            }
            match self.wait(state, until) {
                Ok(next) => state = next,
                Err(last) => {
                    state = last;
                    break None;
                }
            }
        };
        state.waiters -= 1;
        state.last_wait = Some((self.clock)());
        job
    }

    /// Extension side: answer to a probe. Dropped unless that probe is
    /// still waiting.
    pub fn probe_done(&self, request_id: u64, result: Result<ProbeResult, AgentError>) {
        let mut state = self.lock();
        let waiting = matches!(
            state.requests.get(&request_id).map(|r| &r.phase),
            Some(Phase::Probing)
        );
        if waiting && !state.answers.contains_key(&request_id) {
            state.answers.insert(request_id, Answer::Probe(result));
            self.changed.notify_all();
        }
    }

    /// Extension side: answer to a fill. Dropped unless that fill is
    /// still waiting.
    pub fn fill_done(&self, request_id: u64, result: Result<FillResult, AgentError>) {
        let mut state = self.lock();
        let waiting = matches!(
            state.requests.get(&request_id).map(|r| &r.phase),
            Some(Phase::Filling)
        );
        if waiting && !state.answers.contains_key(&request_id) {
            state.answers.insert(request_id, Answer::Fill(result));
            self.changed.notify_all();
        }
    }

    /// True while the extension polls: a `wait_job` is blocked now or
    /// returned within [`LISTENER_TTL`].
    pub fn has_listener(&self) -> bool {
        self.lock().listening((self.clock)())
    }

    /// Host side: true while `request_id` holds an unexpired ticket. Does
    /// not spend it (`plan_fill` asks before the values are asked for).
    pub fn ticket_live(&self, request_id: u64) -> bool {
        let mut state = self.lock();
        state.expire((self.clock)());
        state.tickets.contains_key(&request_id)
    }

    /// Host side: spends the ticket of `request_id` if item, origin (exact
    /// string) and kind match and it has not expired. True once at most.
    /// A mismatch leaves the ticket in place.
    pub fn redeem(&self, request_id: u64, item_id: &str, origin: &str, kind: AgentKind) -> bool {
        let mut state = self.lock();
        state.expire((self.clock)());
        let good = state
            .tickets
            .get(&request_id)
            .is_some_and(|t| t.item_id == item_id && t.origin == origin && t.kind == kind);
        if good {
            state.tickets.remove(&request_id);
        }
        good
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

    /// Marks the extension as listening without taking a job.
    fn listen(hub: &AgentHub) {
        assert!(hub.wait_job(Duration::ZERO).is_none());
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
    fn extension(hub: Arc<AgentHub>, jobs: usize) -> thread::JoinHandle<Vec<bool>> {
        thread::spawn(move || {
            let mut redeemed = Vec::new();
            for _ in 0..jobs {
                match hub.wait_job(LONG) {
                    Some(AgentJob::Probe { request_id, url }) => {
                        hub.probe_done(request_id, Ok(page(&url)));
                    }
                    Some(AgentJob::Fill {
                        request_id,
                        item_id,
                        kind,
                        submit,
                        ..
                    }) => {
                        redeemed.push(hub.redeem(request_id, &item_id, "https://github.com", kind));
                        hub.fill_done(
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
        listen(&hub);
        let out = hub.probe("claude", "https://github.com/login", SHORT);
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        // The unanswered job does not linger for a later listener.
        assert!(hub.wait_job(Duration::ZERO).is_none());
        // The client is free again.
        let ext = extension(Arc::clone(&hub), 1);
        let (_, got) = hub.probe("claude", "https://github.com/x", LONG).unwrap();
        assert_eq!(got.tab_title, "https://github.com/x");
        ext.join().unwrap();
    }

    #[test]
    fn probe_returns_the_extension_result() {
        let (hub, _) = hub();
        listen(&hub);
        let ext = extension(Arc::clone(&hub), 1);
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
        listen(&hub);
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || {
            if let Some(AgentJob::Probe { request_id, .. }) = h.wait_job(LONG) {
                h.probe_done(request_id, Err(AgentError::TabMismatch));
            }
        });
        let out = hub.probe("claude", "https://github.com/login", LONG);
        assert_eq!(out.unwrap_err(), AgentError::TabMismatch);
        ext.join().unwrap();
    }

    #[test]
    fn fill_issues_a_ticket_redeemable_once() {
        let (hub, _) = hub();
        listen(&hub);
        let ext = extension(Arc::clone(&hub), 2);
        let (id, page) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        let out = hub
            .fill(
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
        assert!(!hub.redeem(id, "item-1", "https://github.com", AgentKind::Login));
    }

    #[test]
    fn fill_job_carries_the_probe_document() {
        let (hub, _) = hub();
        listen(&hub);
        let ext = extension(Arc::clone(&hub), 1);
        let (id, page) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let h = Arc::clone(&hub);
        let filler = thread::spawn(move || {
            h.fill(
                id,
                "item-1",
                "https://github.com",
                AgentKind::Card,
                false,
                "doc-9",
                LONG,
            )
        });
        let job = hub.wait_job(LONG).unwrap();
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
        assert!(hub.redeem(id, "item-1", "https://github.com", AgentKind::Card));
        hub.fill_done(id, Err(AgentError::NoFields));
        assert_eq!(filler.join().unwrap().unwrap_err(), AgentError::NoFields);
        let _ = page;
    }

    #[test]
    fn ticket_refused_for_other_item_or_origin() {
        let (hub, _) = hub();
        listen(&hub);
        let ext = extension(Arc::clone(&hub), 1);
        let (id, page) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let h = Arc::clone(&hub);
        let origin = page.origin.clone();
        let filler = thread::spawn(move || {
            h.fill(id, "item-1", &origin, AgentKind::Login, false, "doc", LONG)
        });
        let Some(AgentJob::Fill { request_id, .. }) = hub.wait_job(LONG) else {
            panic!("expected a fill job");
        };
        assert_eq!(request_id, id);
        assert!(!hub.redeem(id, "item-2", "https://github.com", AgentKind::Login));
        assert!(!hub.redeem(id, "item-1", "https://evil.example", AgentKind::Login));
        assert!(!hub.redeem(id, "item-1", "https://gist.github.com", AgentKind::Login));
        assert!(!hub.redeem(id, "item-1", "https://github.com", AgentKind::Card));
        assert!(!hub.redeem(id + 1, "item-1", "https://github.com", AgentKind::Login));
        // Wrong guesses do not burn the ticket.
        assert!(hub.redeem(id, "item-1", "https://github.com", AgentKind::Login));
        hub.fill_done(
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
        listen(&hub);
        let ext = extension(Arc::clone(&hub), 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        // Probed, no fill yet: no ticket.
        assert!(!hub.ticket_live(id));
        let h = Arc::clone(&hub);
        let filler = thread::spawn(move || {
            h.fill(
                id,
                "item-1",
                "https://github.com",
                AgentKind::Login,
                false,
                "doc",
                LONG,
            )
        });
        let Some(AgentJob::Fill { .. }) = hub.wait_job(LONG) else {
            panic!("expected a fill job");
        };
        assert!(hub.ticket_live(id));
        assert!(hub.ticket_live(id));
        assert!(!hub.ticket_live(id + 1));
        assert!(hub.redeem(id, "item-1", "https://github.com", AgentKind::Login));
        assert!(!hub.ticket_live(id));
        hub.fill_done(id, Err(AgentError::Denied));
        assert_eq!(filler.join().unwrap().unwrap_err(), AgentError::Denied);

        // An unspent ticket dies with its TTL.
        let ext = extension(Arc::clone(&hub), 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let h = Arc::clone(&hub);
        let filler = thread::spawn(move || {
            h.fill(
                id,
                "item-1",
                "https://github.com",
                AgentKind::Login,
                false,
                "doc",
                LONG,
            )
        });
        let Some(AgentJob::Fill { .. }) = hub.wait_job(LONG) else {
            panic!("expected a fill job");
        };
        assert!(hub.ticket_live(id));
        now.fetch_add(31, Ordering::SeqCst);
        assert!(!hub.ticket_live(id));
        hub.fill_done(id, Err(AgentError::Denied));
        filler.join().unwrap().unwrap_err();
    }

    #[test]
    fn ticket_refused_after_30s() {
        let (hub, now) = hub();
        listen(&hub);
        let ext = extension(Arc::clone(&hub), 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let h = Arc::clone(&hub);
        let filler = thread::spawn(move || {
            h.fill(
                id,
                "item-1",
                "https://github.com",
                AgentKind::Login,
                false,
                "doc",
                LONG,
            )
        });
        let Some(AgentJob::Fill { .. }) = hub.wait_job(LONG) else {
            panic!("expected a fill job");
        };
        now.fetch_add(31, Ordering::SeqCst);
        assert!(!hub.redeem(id, "item-1", "https://github.com", AgentKind::Login));
        hub.fill_done(id, Err(AgentError::Denied));
        assert_eq!(filler.join().unwrap().unwrap_err(), AgentError::Denied);
    }

    #[test]
    fn fill_refused_for_unknown_request_or_other_origin() {
        let (hub, _) = hub();
        listen(&hub);
        let out = hub.fill(
            42,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "d",
            SHORT,
        );
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        let ext = extension(Arc::clone(&hub), 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let out = hub.fill(
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
        assert!(hub.wait_job(Duration::ZERO).is_none());
        assert!(!hub.redeem(id, "item-1", "https://gitlab.com", AgentKind::Login));
        assert!(!hub.redeem(id, "item-1", "https://github.com", AgentKind::Login));
    }

    #[test]
    fn fill_times_out_and_its_ticket_dies() {
        let (hub, _) = hub();
        listen(&hub);
        let ext = extension(Arc::clone(&hub), 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        let out = hub.fill(
            id,
            "item-1",
            "https://github.com",
            AgentKind::Login,
            false,
            "d",
            SHORT,
        );
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        assert!(hub.wait_job(Duration::ZERO).is_none());
        assert!(!hub.redeem(id, "item-1", "https://github.com", AgentKind::Login));
        // Fill cannot be retried on a finished request.
        let out = hub.fill(
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
        listen(&hub);
        // The extension answers the two probes in reverse order.
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || {
            let mut seen = Vec::new();
            while seen.len() < 2 {
                if let Some(AgentJob::Probe { request_id, url }) = h.wait_job(LONG) {
                    seen.push((request_id, url));
                }
            }
            for (request_id, url) in seen.into_iter().rev() {
                h.probe_done(request_id, Ok(page(&url)));
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
        listen(&hub);
        let ext = extension(Arc::clone(&hub), 1);
        let (id, _) = hub
            .probe("claude", "https://github.com/login", LONG)
            .unwrap();
        ext.join().unwrap();
        // The first request is still open (waiting for fill): the second
        // probe of the same client times out without reaching the extension.
        let out = hub.probe("claude", "https://github.com/other", SHORT);
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        assert!(hub.wait_job(Duration::ZERO).is_none());
        // Another client is not blocked.
        let ext = extension(Arc::clone(&hub), 1);
        assert!(hub.probe("other", "https://github.com/x", LONG).is_ok());
        ext.join().unwrap();
        // Once the first request finishes, the queued probe goes through.
        let h = Arc::clone(&hub);
        let second = thread::spawn(move || h.probe("claude", "https://github.com/next", LONG));
        thread::sleep(SHORT);
        let ext = extension(Arc::clone(&hub), 2);
        let done = hub.fill(
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
        listen(&hub);
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || match h.wait_job(LONG) {
            Some(AgentJob::Probe { request_id, .. }) => request_id,
            _ => panic!("expected a probe"),
        });
        let out = hub.probe("claude", "https://github.com/late", SHORT);
        assert_eq!(out.unwrap_err(), AgentError::Timeout);
        let stale = ext.join().unwrap();
        // The answer arrives after the timeout.
        hub.probe_done(stale, Ok(page("stale")));
        hub.fill_done(
            stale,
            Ok(FillResult {
                filled: vec!["password".to_owned()],
                submitted: false,
            }),
        );
        // The next request of the same client gets its own answer only.
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || match h.wait_job(LONG) {
            Some(AgentJob::Probe { request_id, url }) => {
                h.probe_done(stale, Ok(page("stale again")));
                h.probe_done(request_id, Ok(page(&url)));
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
        listen(&hub);
        let h = Arc::clone(&hub);
        let ext = thread::spawn(move || {
            if let Some(AgentJob::Probe { request_id, .. }) = h.wait_job(LONG) {
                h.fill_done(
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
}
