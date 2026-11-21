//! The remote contact invitation (sharing spec 5.3.2, 13.9), as the Apple
//! apps' `ContactInviteFlow` runs it, over the invite drops of the server
//! the link names:
//!
//! - the inviter makes a link ("Créer un lien") and waits for the reply,
//!   makes the pair's mailbox (decision 16), writes its answer: the contact
//!   is pinned at Link ("Non vérifié");
//! - the invitee pastes the link, writes its sealed reply, keeps its
//!   pending secret (sealed in `mailbox.bin`, for an answer that lands after
//!   a restart) and waits for the answer.
//!
//! Then "Comparer le numéro de sécurité" takes the contact to Verified. A
//! link, a drop id or a secret is never logged.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use onepass_ffi::{FfiInvitePart, OnePassError, Session};
use serde::Serialize;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::state::{AppState, now};
use crate::sync::{self, Server};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How long an invitee waits for the answer (`ContactInviteFlow`).
const ANSWER_WAIT_SECS: i64 = 72 * 3600;
const PENDING_PREFIX: &str = "invite.";

fn poll_interval() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(s) = std::env::var("ONEPASS_INVITE_POLL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        return Duration::from_secs(s.max(1));
    }
    Duration::from_secs(10)
}

/// A contact as the screens show it.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContactView {
    pub account_id: String,
    pub name: String,
    /// "link" (Non vérifié) or "verified".
    pub level: &'static str,
    /// "active", "keysChanged" or "removed".
    pub state: &'static str,
    pub verified_at: i64,
    pub safety_number: String,
}

impl From<onepass_ffi::FfiContact> for ContactView {
    fn from(c: onepass_ffi::FfiContact) -> Self {
        ContactView {
            account_id: c.account_id,
            name: c.name_local,
            level: match c.level {
                onepass_ffi::FfiContactLevel::Link => "link",
                onepass_ffi::FfiContactLevel::Verified => "verified",
            },
            state: match c.state {
                onepass_ffi::FfiContactState::Active => "active",
                onepass_ffi::FfiContactState::KeysChanged { .. } => "keysChanged",
                onepass_ffi::FfiContactState::Removed { .. } => "removed",
            },
            verified_at: c.verified_at,
            safety_number: c.safety_number,
        }
    }
}

/// Where an invitation stands, for the sheet that polls it.
#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    /// "inviter" or "invitee".
    pub role: &'static str,
    /// "creating", "sharing" (the link to send), "replying",
    /// "waitingAnswer", "done" or "failed".
    pub step: &'static str,
    pub link: Option<String>,
    pub expires_at: Option<i64>,
    pub contact: Option<ContactView>,
    /// "expired", "offline", "noSync", "badLink", "own" or "other".
    pub error: Option<&'static str>,
    pub detail: Option<String>,
}

/// The invitation in progress on this PC (one at a time).
pub struct InviteFlow {
    pub view: Arc<Mutex<InviteView>>,
    cancel: Arc<AtomicBool>,
}

impl InviteFlow {
    pub fn view(&self) -> InviteView {
        lock(&self.view).clone()
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

#[derive(Debug)]
enum Failure {
    Cancelled,
    Expired,
    Offline,
    NoSync,
    BadLink,
    Own,
    Other(String),
}

impl From<OnePassError> for Failure {
    fn from(e: OnePassError) -> Self {
        match e {
            OnePassError::MailboxUnavailable { .. }
            | OnePassError::Forbidden
            | OnePassError::ClockSkew => Failure::Offline,
            other => Failure::Other(format!("{other:?}")),
        }
    }
}

impl From<String> for Failure {
    fn from(e: String) -> Self {
        Failure::Other(e)
    }
}

fn set(view: &Mutex<InviteView>, f: impl FnOnce(&mut InviteView)) {
    f(&mut lock(view));
}

fn fail(view: &Mutex<InviteView>, f: Failure) {
    let (code, detail) = match f {
        Failure::Cancelled => return,
        Failure::Expired => ("expired", None),
        Failure::Offline => ("offline", None),
        Failure::NoSync => ("noSync", None),
        Failure::BadLink => ("badLink", None),
        Failure::Own => ("own", None),
        Failure::Other(d) => ("other", Some(d)),
    };
    set(view, |v| {
        v.step = "failed";
        v.error = Some(code);
        v.detail = detail;
    });
}

/// The name this account's card carries: the profile name, else the PC's.
fn my_name(session: &Session) -> String {
    session
        .profile()
        .ok()
        .flatten()
        .map(|p| p.name)
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(crate::commands::device_name)
}

/// Reads one half of the invitation until it is all there.
fn poll(
    server: &Server,
    rdv: &[u8],
    part: FfiInvitePart,
    until: i64,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, Failure> {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Failure::Cancelled);
        }
        if let Ok(Some(b)) = onepass_ffi::invite_get(
            server.base_url.clone(),
            rdv.to_vec(),
            part,
            server.ca_pem.clone(),
        ) {
            return Ok(b);
        }
        if now() >= until {
            return Err(Failure::Expired);
        }
        let step = Duration::from_millis(250);
        let mut waited = Duration::ZERO;
        while waited < poll_interval() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Failure::Cancelled);
            }
            std::thread::sleep(step);
            waited += step;
        }
    }
}

/// Writes one half, a few times over a bad network.
fn put(server: &Server, rdv: &[u8], part: FfiInvitePart, bytes: &[u8]) -> Result<(), Failure> {
    let mut last = Failure::Offline;
    for attempt in 0..5 {
        match onepass_ffi::invite_put(
            server.base_url.clone(),
            rdv.to_vec(),
            part,
            bytes.to_vec(),
            server.ca_pem.clone(),
        ) {
            // Written before a cut: the same bytes are there.
            Ok(()) | Err(OnePassError::Conflict) => return Ok(()),
            Err(e) => last = e.into(),
        }
        std::thread::sleep(Duration::from_secs(1 << attempt));
    }
    Err(last)
}

fn start(
    app: &AppHandle,
    role: &'static str,
    step: &'static str,
    run: impl FnOnce(&AppHandle, &Mutex<InviteView>, &AtomicBool) -> Result<(), Failure>
    + Send
    + 'static,
) {
    let state = app.state::<AppState>();
    if let Some(old) = lock(&state.invite).take() {
        old.cancel();
    }
    let view = Arc::new(Mutex::new(InviteView {
        role,
        step,
        ..InviteView::default()
    }));
    let cancel = Arc::new(AtomicBool::new(false));
    *lock(&state.invite) = Some(InviteFlow {
        view: view.clone(),
        cancel: cancel.clone(),
    });
    let app = app.clone();
    std::thread::spawn(move || {
        if let Err(f) = run(&app, &view, &cancel) {
            fail(&view, f);
        }
    });
}

// ---- the inviter ----------------------------------------------------------------------

/// "Créer un lien": a new invitation on the OnePass server, then the wait
/// for the reply, the pair's mailbox and the answer.
pub fn start_inviter(app: &AppHandle, session: Arc<Session>) {
    start(app, "inviter", "creating", move |app, view, cancel| {
        let server = sync::hosted();
        let host = crate::zones::link_host(&server);
        let invite = session.create_contact_invite(host, now())?;
        set(view, |v| {
            v.step = "sharing";
            v.link = Some(invite.link.clone());
            v.expires_at = Some(invite.expires_at);
        });
        let reply = Zeroizing::new(poll(
            &server,
            &invite.rdv_id,
            FfiInvitePart::Reply,
            invite.expires_at,
            cancel,
        )?);
        let card = session.invite_reply_card(invite.invite_id.clone(), reply.to_vec(), now())?;
        let state = app.state::<AppState>();
        let zones = state.sync.zones.client().ok_or(Failure::NoSync)?;
        // Decision 16: the pair's mailbox first, then the pin.
        let offer = zones
            .handle
            .contact_zone_create(session.clone(), card, now())?;
        let answer = session.accept_invite_reply(
            invite.invite_id.clone(),
            reply.to_vec(),
            my_name(&session),
            offer,
            now(),
        )?;
        state.sync.changed();
        put(
            &server,
            &invite.rdv_id,
            FfiInvitePart::Answer,
            &answer.answer,
        )?;
        let _ = onepass_ffi::invite_delete(
            server.base_url.clone(),
            invite.rdv_id.clone(),
            FfiInvitePart::Reply,
            server.ca_pem.clone(),
        );
        set(view, |v| {
            v.step = "done";
            v.link = None;
            v.contact = Some(answer.contact.into());
        });
        Ok(())
    });
}

// ---- the invitee ----------------------------------------------------------------------

/// The pending reply kept for `rdv`: the server's URL, then the core's bytes.
fn encode_pending(server: &Server, pending: &[u8]) -> Zeroizing<Vec<u8>> {
    let url = server.base_url.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(2 + url.len() + pending.len()));
    out.extend_from_slice(&u16::try_from(url.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(url);
    out.extend_from_slice(pending);
    out
}

fn decode_pending(bytes: &[u8]) -> Option<(Server, Zeroizing<Vec<u8>>)> {
    let len = usize::from(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?));
    let url = std::str::from_utf8(bytes.get(2..2 + len)?).ok()?.to_owned();
    let pending = Zeroizing::new(bytes.get(2 + len..)?.to_vec());
    let ca_pem = sync::ca_for(&url, None);
    Some((
        Server {
            base_url: url,
            ca_pem,
        },
        pending,
    ))
}

fn pending_key(rdv: &[u8]) -> String {
    format!(
        "{PENDING_PREFIX}{}",
        rdv.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// A pasted link: the reply is written, then the answer awaited.
pub fn start_invitee(app: &AppHandle, session: Arc<Session>, link: String) {
    let link = Zeroizing::new(link.trim().to_owned());
    start(app, "invitee", "replying", move |app, view, cancel| {
        let server = crate::zones::server_for_link(&link);
        let reply = session
            .contact_invite_reply(link.to_string(), my_name(&session), now())
            .map_err(|e| match e {
                OnePassError::InvalidInput { .. } | OnePassError::Integrity { .. } => {
                    Failure::BadLink
                }
                other => other.into(),
            })?;
        let state = app.state::<AppState>();
        let pending = Zeroizing::new(reply.pending.to_bytes());
        sync::store_seed(
            &state,
            &pending_key(&reply.rdv_id),
            &encode_pending(&server, &pending),
        )?;
        put(&server, &reply.rdv_id, FfiInvitePart::Reply, &reply.bytes)?;
        set(view, |v| v.step = "waitingAnswer");
        await_answer(
            app,
            &session,
            &server,
            &pending,
            now() + ANSWER_WAIT_SECS,
            view,
            cancel,
        )
    });
}

fn await_answer(
    app: &AppHandle,
    session: &Session,
    server: &Server,
    pending_bytes: &[u8],
    until: i64,
    view: &Mutex<InviteView>,
    cancel: &AtomicBool,
) -> Result<(), Failure> {
    let pending = onepass_ffi::pending_invite_from_bytes(pending_bytes.to_vec())?;
    let rdv = pending.rdv_id();
    let answer = Zeroizing::new(poll(server, &rdv, FfiInvitePart::Answer, until, cancel)?);
    let state = app.state::<AppState>();
    let contact = match session.finish_invite(pending, answer.to_vec(), now()) {
        Ok(c) => c,
        // The inviter is this account (a link opened on its own PC).
        Err(OnePassError::Validation { field, .. }) if field == "contact" => {
            let _ = sync::delete_seed(&state, &pending_key(&rdv));
            return Err(Failure::Own);
        }
        Err(e) => return Err(e.into()),
    };
    let _ = sync::delete_seed(&state, &pending_key(&rdv));
    let _ = onepass_ffi::invite_delete(
        server.base_url.clone(),
        rdv,
        FfiInvitePart::Answer,
        server.ca_pem.clone(),
    );
    state.sync.changed();
    set(view, |v| {
        v.step = "done";
        v.contact = Some(contact.into());
    });
    Ok(())
}

/// After an unlock: a reply written before a restart waits for its answer
/// again (`ContactInviteFlow.resume`), unless a flow already runs.
pub fn resume_pending(app: &AppHandle) {
    let state = app.state::<AppState>();
    if lock(&state.invite).is_some() {
        return;
    }
    let Some(session) = state.session() else {
        return;
    };
    let Ok(entries) = sync::seeds_with_prefix(&state, PENDING_PREFIX) else {
        return;
    };
    let Some((_, bytes)) = entries.into_iter().next() else {
        return;
    };
    let Some((server, pending)) = decode_pending(&bytes) else {
        return;
    };
    start(app, "invitee", "waitingAnswer", move |app, view, cancel| {
        await_answer(
            app,
            &session,
            &server,
            &pending,
            now() + ANSWER_WAIT_SECS,
            view,
            cancel,
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_round_trip() {
        let server = Server {
            base_url: "https://sync.example.org/functions/v1/mailbox".into(),
            ca_pem: None,
        };
        let bytes = encode_pending(&server, &[1, 2, 3]);
        let (s, p) = decode_pending(&bytes).unwrap();
        assert_eq!(s.base_url, server.base_url);
        assert_eq!(p.as_slice(), &[1, 2, 3]);
        assert!(decode_pending(&[0, 9]).is_none());
        assert_eq!(pending_key(&[0xab, 0x01]), "invite.ab01");
    }
}
