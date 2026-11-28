//! Adding a device (spec 2b 5, cross-platform 5.3, 4.12): the code
//! direction of the Mac's "Configurer un appareil" (HostDeviceSheet) and the
//! iPhone's "Saisis le code" (JoinCodeSteps), over the rendezvous of the
//! account's mailbox (T-RDV). The core holds every cryptographic state; this
//! module only moves its opaque frames and tells the UI where it stands.
//!
//! - This PC shows a code (QR and `XXXX-XXXX`), renewed every 30 s. A new
//!   device types it, both screens show the same 6 digits, the user types
//!   them here (T-RDV gives no proximity, spec 5.3) with the master
//!   password, and the account is granted with an enroll ticket for the new
//!   device's mailbox credential.
//! - The new device types the code, compares the 6 digits, receives the
//!   grant, asks the master password, imports, then joins the mailbox.
//!
//! Nothing here logs a frame, a code or a key.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use onepass_ffi::{FfiDeviceMode, FfiPairingMessage, OnePassError, PairingHost, PairingNewcomer};
use onepass_mailbox::{Endpoint, MailboxError, RdvRole, Rendezvous};
use serde::Serialize;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::device::SoftwareHalf;
use crate::secrets::DeviceSecrets;
use crate::state::{AppState, now};
use crate::sync::{self, Backend, Home, Server};

/// Largest frame before the key exchange (`PairingFrame.maxHandshakeBytes`).
const HANDSHAKE_MAX: usize = 16 << 10;
/// Largest frame (`PairingFrame.maxBytes`).
const FRAME_MAX: usize = 64 << 20;
/// A new code this often (HostDeviceSheet).
const RENEW: Duration = Duration::from_secs(30);
/// One read of the rendezvous waits at most this long, then looks whether
/// the user cancelled.
const SLICE: Duration = Duration::from_secs(10);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Qr {
    pub modules: Vec<bool>,
    pub width: usize,
}

/// What the pairing screens show.
#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct PairView {
    /// "host" (this PC adds a device) or "join" (this PC is the new one).
    pub role: &'static str,
    /// Host: "connecting", "hosting", "comparing", "waitingForPeer",
    /// "granting", "done", "failed". Join: "connecting", "comparing",
    /// "waitingForApproval", "password", "importing", "done", "failed".
    pub step: &'static str,
    /// Host: the code to type (`XXXX-XXXX`) and its QR.
    pub code: Option<String>,
    pub qr: Option<Qr>,
    pub expires_at: Option<i64>,
    /// Join: the 6 digits to compare. Never sent to the host's screen,
    /// where the user types what the new device shows.
    pub sas: Option<String>,
    pub peer_name: Option<String>,
    pub peer_kind: Option<String>,
    /// The new device confirmed the code on its side.
    pub peer_confirmed: bool,
    /// Join: the last master password was wrong.
    pub wrong_password: bool,
    /// "noMailbox", "refused", "codeRejected", "connectionLost",
    /// "timeout", "offline", "cancelled", or "other".
    pub error: Option<String>,
    pub detail: Option<String>,
}

enum Event {
    /// Host: the user typed the right digits and the master password.
    Approve,
    /// Join: "Les codes sont identiques".
    Confirm,
    /// Join: the master password, to import the grant.
    Password(Zeroizing<String>),
}

/// A pairing in progress on this PC.
pub struct Pairing {
    pub role: &'static str,
    view: Arc<Mutex<PairView>>,
    tx: mpsc::Sender<Event>,
    cancel: Arc<AtomicBool>,
    /// Host: the 6 digits the user must type.
    sas: Arc<Mutex<Option<String>>>,
}

impl Pairing {
    pub fn view(&self) -> PairView {
        lock(&self.view).clone()
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    /// Host: the typed digits match the new device's.
    pub fn sas_matches(&self, typed: &str) -> bool {
        let typed: String = typed.chars().filter(char::is_ascii_digit).collect();
        lock(&self.sas).as_deref().is_some_and(|s| {
            let want: String = s.chars().filter(char::is_ascii_digit).collect();
            !want.is_empty() && want == typed
        })
    }

    pub fn approve(&self) {
        {
            let mut v = lock(&self.view);
            v.step = if v.peer_confirmed {
                "granting"
            } else {
                "waitingForPeer"
            };
        }
        let _ = self.tx.send(Event::Approve);
    }

    pub fn confirm(&self) {
        let _ = self.tx.send(Event::Confirm);
    }

    pub fn password(&self, p: Zeroizing<String>) {
        {
            let mut v = lock(&self.view);
            v.step = "importing";
            v.wrong_password = false;
        }
        let _ = self.tx.send(Event::Password(p));
    }
}

/// Why a pairing stopped, for the UI.
struct Failure(&'static str, Option<String>);

impl From<MailboxError> for Failure {
    fn from(e: MailboxError) -> Self {
        match e {
            MailboxError::Offline => Failure("offline", None),
            MailboxError::Server(onepass_mailbox::ErrorCode::NotFound) => {
                Failure("connectionLost", None)
            }
            e => Failure("other", Some(e.to_string())),
        }
    }
}

impl From<OnePassError> for Failure {
    fn from(e: OnePassError) -> Self {
        match e {
            OnePassError::MailboxUnavailable { .. } => Failure("offline", None),
            e => Failure("other", Some(format!("{e:?}"))),
        }
    }
}

impl From<String> for Failure {
    fn from(e: String) -> Self {
        Failure("other", Some(e))
    }
}

fn session_id(service_name: &str) -> Result<[u8; 16], Failure> {
    let bad = || Failure("other", Some("service name".into()));
    if service_name.len() != 32 {
        return Err(bad());
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&service_name[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn qr(text: &str) -> Option<Qr> {
    let code =
        qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M).ok()?;
    Some(Qr {
        width: code.width(),
        modules: code
            .to_colors()
            .into_iter()
            .map(|c| c == qrcode::Color::Dark)
            .collect(),
    })
}

/// Reads the next frame within `patience`, a slice at a time, giving up
/// when the user cancels.
fn recv(
    rdv: &mut Rendezvous,
    max: usize,
    patience: Duration,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, Failure> {
    let end = Instant::now() + patience;
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(Failure("cancelled", None));
        }
        let now = Instant::now();
        if now >= end {
            return Err(Failure("timeout", None));
        }
        match rdv.recv_frame(max, now + SLICE.min(end - now)) {
            Ok(f) => return Ok(f),
            Err(MailboxError::Offline) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Waits for the user's next event, giving up when they cancel.
fn wait_event(rx: &mpsc::Receiver<Event>, cancel: &AtomicBool) -> Result<Event, Failure> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(Failure("cancelled", None));
        }
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(e) => return Ok(e),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Failure("cancelled", None)),
        }
    }
}

pub(crate) fn kind_key(k: onepass_ffi::FfiDeviceKind) -> &'static str {
    use onepass_ffi::FfiDeviceKind as K;
    match k {
        K::Phone => "phone",
        K::Tablet => "tablet",
        K::Mac => "mac",
        K::Vision => "vision",
        K::Android => "android",
        K::Windows => "windows",
        K::Linux => "linux",
        K::Other => "other",
    }
}

fn start(
    handle: &AppHandle,
    role: &'static str,
    run: impl FnOnce(
        AppHandle,
        Arc<Mutex<PairView>>,
        mpsc::Receiver<Event>,
        Arc<AtomicBool>,
        Arc<Mutex<Option<String>>>,
    ) + Send
    + 'static,
) {
    let state = handle.state::<AppState>();
    if let Some(old) = lock(&state.pairing).take() {
        old.cancel();
    }
    let view = Arc::new(Mutex::new(PairView {
        role,
        step: "connecting",
        ..PairView::default()
    }));
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let sas = Arc::new(Mutex::new(None));
    *lock(&state.pairing) = Some(Pairing {
        role,
        view: view.clone(),
        tx,
        cancel: cancel.clone(),
        sas: sas.clone(),
    });
    let handle = handle.clone();
    std::thread::spawn(move || run(handle, view, rx, cancel, sas));
}

fn fail(view: &Mutex<PairView>, f: Failure) {
    let mut v = lock(view);
    if v.step != "done" {
        v.step = "failed";
        v.error = Some(f.0.into());
        v.detail = f.1;
    }
}

// ---- this PC adds a device ------------------------------------------------------------

/// "Ajouter un appareil": show codes until a new device proves one.
pub fn start_host(handle: &AppHandle) {
    start(handle, "host", |handle, view, rx, cancel, sas| {
        if let Err(f) = host(&handle, &view, &rx, &cancel, &sas) {
            fail(&view, f);
        }
    });
}

fn host(
    handle: &AppHandle,
    view: &Mutex<PairView>,
    rx: &mpsc::Receiver<Event>,
    cancel: &Arc<AtomicBool>,
    sas_slot: &Mutex<Option<String>>,
) -> Result<(), Failure> {
    let state = handle.state::<AppState>();
    // A setup still pending is finished first (one round).
    if !matches!(sync::backend(&state), Backend::Mailbox { .. }) || state.sync.client().is_none() {
        state.sync.sync_now_blocking(Duration::from_secs(60));
    }
    let Some((home, client)) = state.sync.client() else {
        return Err(Failure("noMailbox", None));
    };
    let endpoint = Endpoint {
        base_url: home.base_url.clone(),
        extra_ca_pem: home.ca_pem.clone(),
    };
    let host = PairingHost::new()?;
    let (htx, hrx) = mpsc::channel::<(Vec<u8>, Rendezvous)>();
    let stop = Arc::new(AtomicBool::new(false));
    let mut next_issue = Instant::now();
    let (approver, mut rdv) = loop {
        if cancel.load(Ordering::Acquire) {
            stop.store(true, Ordering::Release);
            host.close();
            return Err(Failure("cancelled", None));
        }
        if Instant::now() >= next_issue {
            let code = host.issue(now())?;
            {
                let mut v = lock(view);
                v.step = "hosting";
                v.qr = qr(&code.qr_text);
                v.code = Some(code.short_text.clone());
                v.expires_at = Some(code.expires_at);
            }
            let session = session_id(&code.service_name)?;
            let (endpoint, htx, stop) = (endpoint.clone(), htx.clone(), stop.clone());
            let expires = code.expires_at;
            std::thread::spawn(move || listen(endpoint, session, expires, &htx, &stop));
            next_issue = Instant::now() + RENEW;
        }
        let wait = next_issue
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(500));
        match hrx.recv_timeout(wait) {
            Ok((hello, rdv)) => match host.accept(hello, now()) {
                Ok(a) => break (a, rdv),
                // Wrong code or a malformed Hello: that one is dropped. Too
                // many close the host.
                Err(_) => {
                    drop(rdv);
                    if !host.is_open() {
                        stop.store(true, Ordering::Release);
                        return Err(Failure("refused", None));
                    }
                }
            },
            Err(_) => continue,
        }
    };
    stop.store(true, Ordering::Release);
    rdv.send_frame(&approver.key_exchange())?;
    let peer = approver.peer();
    *lock(sas_slot) = Some(approver.sas());
    {
        let mut v = lock(view);
        v.step = "comparing";
        v.qr = None;
        v.code = None;
        v.peer_name = Some(peer.name.clone());
        v.peer_kind = Some(kind_key(peer.kind).into());
    }
    if approver.requested_mode() == FfiDeviceMode::Public {
        return Err(Failure("other", Some("public".into())));
    }
    // The new device's confirmation (it may come before or after the user here).
    let frame = recv(&mut rdv, FRAME_MAX, Duration::from_secs(300), cancel)?;
    match approver.on_frame(frame)? {
        FfiPairingMessage::Confirmed => {}
        FfiPairingMessage::End => return Err(Failure("codeRejected", None)),
        _ => return Err(Failure("other", Some("unexpected frame".into()))),
    }
    {
        let mut v = lock(view);
        v.peer_confirmed = true;
        if v.step == "waitingForPeer" {
            v.step = "granting";
        }
    }
    loop {
        if let Event::Approve = wait_event(rx, cancel)? {
            break;
        }
    }
    lock(view).step = "granting";
    // The snapshot is the server's rows: sync just before (PairingApproverFlow).
    state.sync.sync_now_blocking(Duration::from_secs(90));
    let session = state
        .session()
        .ok_or(Failure("other", Some("locked".into())))?;
    let secrets = state
        .load_secrets()?
        .ok_or(Failure("other", Some("device".into())))?;
    let grant = approver.seal_full_grant(
        session.clone(),
        secrets.secret_key.to_string(),
        approver.requested_mode(),
        false,
        Some(client),
    )?;
    rdv.send_frame(&grant)?;
    // The device list changed: sent now.
    state.sync.changed();
    let frame = recv(&mut rdv, FRAME_MAX, Duration::from_secs(300), cancel)?;
    if let FfiPairingMessage::Ack = approver.on_frame(frame)? {
        approver.introduce(
            session,
            secrets.classical.to_vec(),
            SoftwareHalf::open(&secrets.pq)?,
        )?;
    }
    state.sync.changed();
    state.sync.kick();
    lock(view).step = "done";
    rdv.close();
    Ok(())
}

/// Waits on one code's rendezvous until a Hello comes, the code expires
/// or another code won.
fn listen(
    endpoint: Endpoint,
    session: [u8; 16],
    expires_at: i64,
    found: &mpsc::Sender<(Vec<u8>, Rendezvous)>,
    stop: &AtomicBool,
) {
    let Ok(mut rdv) = Rendezvous::new(endpoint, session, RdvRole::Approver) else {
        return;
    };
    loop {
        let left = expires_at - now();
        if stop.load(Ordering::Acquire) || left <= 0 {
            return;
        }
        let slice = SLICE.min(Duration::from_secs(left.unsigned_abs()));
        match rdv.recv_frame(HANDSHAKE_MAX, Instant::now() + slice) {
            Ok(hello) => {
                let _ = found.send((hello, rdv));
                return;
            }
            Err(MailboxError::Offline) => {}
            Err(_) => return,
        }
    }
}

// ---- this PC is the new device ------------------------------------------------------

/// "Ajouter cet appareil": join the device showing `code`, through `server`.
pub fn start_join(handle: &AppHandle, code: String, server: Server) {
    start(handle, "join", move |handle, view, rx, cancel, _| {
        if let Err(f) = join(&handle, &view, &rx, &cancel, &code, &server) {
            fail(&view, f);
        }
    });
}

fn join(
    handle: &AppHandle,
    view: &Mutex<PairView>,
    rx: &mpsc::Receiver<Event>,
    cancel: &AtomicBool,
    code: &str,
    server: &Server,
) -> Result<(), Failure> {
    let state = handle.state::<AppState>();
    if !sync::store_is_empty(&state.data_dir().join("vault.db")) {
        return Err(Failure(
            "other",
            Some("an account already exists on this PC".into()),
        ));
    }
    let credential = onepass_ffi::mailbox_generate_credential()?;
    let credential_seed = Zeroizing::new(credential.seed.clone());
    let newcomer = PairingNewcomer::join_code(
        crate::commands::device_name(),
        crate::commands::device_kind(),
        FfiDeviceMode::Personal,
        code.to_owned(),
        now(),
        Some(credential.public_key.clone()),
    )
    .map_err(|_| Failure("refused", None))?;
    let session = session_id(&newcomer.service_name())?;
    let endpoint = Endpoint {
        base_url: server.base_url.clone(),
        extra_ca_pem: server.ca_pem.clone(),
    };
    let mut rdv = Rendezvous::new(endpoint, session, RdvRole::Newcomer)?;
    rdv.send_frame(&newcomer.hello())?;
    let kx = recv(&mut rdv, HANDSHAKE_MAX, Duration::from_secs(120), cancel)?;
    let sas = newcomer
        .on_key_exchange(kx, now())
        .map_err(|_| Failure("refused", None))?;
    {
        let mut v = lock(view);
        v.step = "comparing";
        v.sas = Some(sas);
    }
    loop {
        if let Event::Confirm = wait_event(rx, cancel)? {
            break;
        }
    }
    // This device's keys, kept in memory until the account is in.
    let classical = Zeroizing::new(onepass_ffi::generate_classical_device_keys()?);
    let pq = SoftwareHalf::generate()?;
    let confirm = newcomer.confirm_with_key(classical.to_vec(), SoftwareHalf::open(&pq)?)?;
    rdv.send_frame(&confirm)?;
    lock(view).step = "waitingForApproval";
    loop {
        let frame = recv(&mut rdv, FRAME_MAX, Duration::from_secs(600), cancel)?;
        match newcomer.open(frame)? {
            FfiPairingMessage::FullGrant { .. } => break,
            FfiPairingMessage::Profile { .. } => continue,
            FfiPairingMessage::End => return Err(Failure("codeRejected", None)),
            _ => return Err(Failure("other", Some("unexpected frame".into()))),
        }
    }
    lock(view).step = "password";
    let unlocked = loop {
        let Event::Password(p) = wait_event(rx, cancel)? else {
            continue;
        };
        match newcomer.import_snapshot_v2(
            state.db_path(),
            p.to_string(),
            classical.to_vec(),
            SoftwareHalf::open(&pq)?,
        ) {
            Ok(u) => break u,
            Err(OnePassError::WrongPassword) => {
                let mut v = lock(view);
                v.step = "password";
                v.wrong_password = true;
            }
            Err(e) => return Err(e.into()),
        }
    };
    drop(Zeroizing::new(unlocked.auk));
    let ack = newcomer.seal_key_ack(classical.to_vec(), SoftwareHalf::open(&pq)?)?;
    let _ = rdv.send_frame(&ack);
    let secret_key = newcomer
        .take_secret_key()
        .ok_or(Failure("other", Some("secret key".into())))?;
    let rng_seed = Zeroizing::new(onepass_ffi::new_device_rng_seed()?);
    let _ = onepass_ffi::set_device_rng_seed(rng_seed.to_vec());
    let secrets = DeviceSecrets {
        account_id: unlocked.session.account_id(),
        secret_key: Zeroizing::new(secret_key),
        classical,
        pq,
        rng_seed,
    };
    if let Err(e) = state.save_secrets(&secrets) {
        unlocked.session.lock();
        let _ = onepass_ffi::reset_store(state.db_path());
        return Err(e.into());
    }
    // The mailbox the grant names, with the enroll ticket for this device.
    // The account is in either way: a failed enrollment leaves this PC
    // unsynced (Settings > Sync says so), never without its account.
    let enrolled = (|| -> Result<(), Failure> {
        if let Some(enrollment) = newcomer.mailbox_enrollment()?
            && let onepass_ffi::FfiSyncBackend::Mailbox { base_url, .. } = &enrollment.home.backend
        {
            let ca = sync::ca_for(base_url, server.ca_pem.clone());
            let joined = onepass_ffi::mailbox_enroll(
                credential_seed.to_vec(),
                enrollment.ticket,
                ca.clone(),
            )?;
            sync::store_seed(&state, &joined.mailbox_id, &credential_seed)?;
            sync::set_backend(
                &state,
                &Backend::Mailbox {
                    home: Home {
                        base_url: joined.base_url,
                        mailbox_id: joined.mailbox_id,
                        ca_pem: ca,
                    },
                },
            )?;
        }
        Ok(())
    })();
    state.set_session(unlocked.session);
    state.sync.reset();
    {
        let mut v = lock(view);
        v.step = "done";
        if let Err(f) = enrolled {
            v.error = Some("enrollFailed".into());
            v.detail = f.1.or(Some(f.0.into()));
        }
    }
    rdv.close();
    Ok(())
}
