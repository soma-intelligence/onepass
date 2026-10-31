//! Key rotation v2 over the UniFFI surface, called as plain Rust (Task 17):
//! rotate, the prompt, follow, reject, the quarantine, the Emergency Kit,
//! the migration of legacy devices and the error kinds. A Rust
//! `FfiPqDeviceHalf` with software keys stands in for the Secure Enclave
//! the app uses. Temp stores stand for devices; `Server` is an append-only
//! log of pushed rows each device fetches from. Synthetic data only. Run
//! with `--features dev-fast-kdf` (debug assertions).

use std::cell::Cell;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use onepass_core::device_keys::{PqDeviceHalf, SoftwarePqHalf};
use onepass_ffi::*;
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};
const WEEK: u64 = 7 * 86_400;

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn now_u() -> u64 {
    u64::try_from(now()).unwrap()
}

// ---- the app's post-quantum half ----------------------------------------------

/// The Secure Enclave stand-in: software keys, and switches that make it
/// fail as a foreign implementation can.
struct Half {
    inner: SoftwarePqHalf,
    fail_sign: Arc<AtomicBool>,
    fail_decap: Arc<AtomicBool>,
}

fn crypto() -> OnePassError {
    OnePassError::Crypto
}

impl FfiPqDeviceHalf for Half {
    fn mldsa_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.inner.mldsa_public().map_err(|_| crypto())
    }

    fn mlkem_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.inner.mlkem_public().map_err(|_| crypto())
    }

    fn mldsa_sign(&self, message: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        if self.fail_sign.load(Ordering::SeqCst) {
            return Err(OnePassError::Locked);
        }
        self.inner.mldsa_sign(&message).map_err(|_| crypto())
    }

    fn mlkem_decapsulate(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        if self.fail_decap.load(Ordering::SeqCst) {
            return Err(OnePassError::Locked);
        }
        Ok(self
            .inner
            .mlkem_decapsulate(&ciphertext)
            .map_err(|_| crypto())?
            .to_vec())
    }
}

/// What the app keeps in its Keychain item `device.<account_id>`.
struct Keys {
    classical: Vec<u8>,
    pq: Vec<u8>,
    fail_sign: Arc<AtomicBool>,
    fail_decap: Arc<AtomicBool>,
}

impl Keys {
    fn new() -> Keys {
        Keys {
            classical: generate_classical_device_keys().unwrap(),
            pq: SoftwarePqHalf::generate().unwrap().to_bytes().to_vec(),
            fail_sign: Arc::new(AtomicBool::new(false)),
            fail_decap: Arc::new(AtomicBool::new(false)),
        }
    }

    fn half(&self) -> Arc<dyn FfiPqDeviceHalf> {
        Arc::new(Half {
            inner: SoftwarePqHalf::from_bytes(&self.pq).unwrap(),
            fail_sign: self.fail_sign.clone(),
            fail_decap: self.fail_decap.clone(),
        })
    }

    fn c(&self) -> Vec<u8> {
        self.classical.clone()
    }
}

// ---- devices and the server ------------------------------------------------------

#[derive(Default)]
struct Server {
    rows: Vec<FfiRemoteRecord>,
}

struct Device {
    _dir: TempDir,
    path: String,
    session: Arc<Session>,
    secret_key: String,
    keys: Keys,
    cursor: Cell<usize>,
}

fn db_path(dir: &Path) -> String {
    dir.join("onepass.db").to_string_lossy().into_owned()
}

/// Every pending row of `path` goes up, phase after phase (a rotation
/// pushes its phases in order: the next shows once the last is confirmed).
fn push(server: &mut Server, path: &str) {
    let h = open_sync_store(path.into()).unwrap();
    for _ in 0..8 {
        let changes = h.pending_changes().unwrap();
        if changes.is_empty() {
            return;
        }
        for c in changes {
            h.mark_pushed(c.kind, c.id.clone(), c.version, Some(b"tag".to_vec()))
                .unwrap();
            server.rows.push(FfiRemoteRecord {
                kind: c.kind,
                id: c.id,
                version: c.version,
                data: c.data,
                server_meta: Some(b"tag".to_vec()),
            });
        }
    }
    panic!("pending rows never settle");
}

/// Fetch what the server got since the last fetch, with the app's clock
/// `now`: the sync contract runs inside the commit.
fn pull_at(server: &Server, path: &str, cursor: &Cell<usize>, now: u64) -> FfiRemoteCommit {
    let h = open_sync_store(path.into()).unwrap();
    for r in &server.rows[cursor.get()..] {
        h.stage_remote(r.clone()).unwrap();
    }
    cursor.set(server.rows.len());
    h.commit_remote_checked(now).unwrap()
}

fn pull(server: &Server, d: &Device) -> FfiRemoteCommit {
    pull_at(server, &d.path, &d.cursor, now_u())
}

fn login(session: &Session, title: &str, password: &str) -> FfiItem {
    let vault = session.vaults().unwrap()[0].id.clone();
    let mut item = session
        .new_item(vault, FfiItemType::Login, title.into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match f.id.as_str() {
            "username" => {
                f.value = FfiFieldValue::Text {
                    value: "camille@exemple.fr".into(),
                }
            }
            "password" => {
                f.value = FfiFieldValue::Password {
                    value: password.into(),
                }
            }
            _ => {}
        }
    }
    item
}

/// A key rotation v2 account on its own device ("Mac de Camille"), one
/// login saved, everything pushed.
fn first_device(server: &mut Server) -> Device {
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let keys = Keys::new();
    let created = create_account_v2(
        path.clone(),
        PASSWORD.into(),
        Some(FAST),
        keys.c(),
        keys.half(),
        "Mac de Camille".into(),
        FfiDeviceKind::Mac,
        FfiDeviceMode::Personal,
    )
    .unwrap();
    created
        .session
        .save_item(login(
            &created.session,
            "Messagerie exemple.fr",
            "pw-atlas-1",
        ))
        .unwrap();
    push(server, &path);
    let d = Device {
        _dir: dir,
        path,
        session: created.session,
        secret_key: created.secret_key,
        keys,
        cursor: Cell::new(0),
    };
    pull(server, &d);
    d
}

/// A full v2 pairing of a new device with `a`, through the FFI only: the
/// newcomer confirms with its key, gets a `FullV2`, imports it and
/// acknowledges; the approver introduces it. Both synced.
fn pair_v2(server: &mut Server, a: &Device, name: &str) -> Device {
    let keys = Keys::new();
    let n = PairingNewcomer::new(
        name.into(),
        FfiDeviceKind::Tablet,
        FfiDeviceMode::Personal,
        now(),
    )
    .unwrap();
    let ap = PairingApprover::begin(n.qr_text(), n.hello(), now()).unwrap();
    assert!(!ap.is_known_device(a.session.clone()).unwrap());
    n.on_key_exchange(ap.key_exchange(), now()).unwrap();
    let f = n.confirm_with_key(keys.c(), keys.half()).unwrap();
    assert_eq!(ap.on_frame(f).unwrap(), FfiPairingMessage::Confirmed);
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
        )
        .unwrap();
    assert!(matches!(
        n.open(frame).unwrap(),
        FfiPairingMessage::FullGrant { .. }
    ));
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let unlocked = n.import_snapshot_v2(path.clone(), PASSWORD.into()).unwrap();
    let ack = n.seal_key_ack(keys.c(), keys.half()).unwrap();
    assert_eq!(ap.on_frame(ack).unwrap(), FfiPairingMessage::Ack);
    ap.introduce(a.session.clone(), a.keys.c(), a.keys.half())
        .unwrap();
    assert!(
        ap.introduce(a.session.clone(), a.keys.c(), a.keys.half())
            .is_err()
    );
    push(server, &a.path);
    let d = Device {
        _dir: dir,
        path,
        session: unlocked.session,
        secret_key: n.take_secret_key().unwrap(),
        keys,
        cursor: Cell::new(0),
    };
    pull(server, &d);
    push(server, &d.path);
    pull(server, a);
    d
}

fn rotate(d: &Device, revoke: Vec<String>, keep_tofu: Vec<String>) -> (FfiRotationOutcome, String) {
    let new_sk = generate_secret_key().unwrap();
    let reason = if revoke.is_empty() {
        FfiRotationReason::Rotate
    } else {
        FfiRotationReason::Revoke
    };
    let out = d
        .session
        .rotate_keys(
            FfiRotateRequest {
                revoke,
                new_password: None,
                password: PASSWORD.into(),
                secret_key: d.secret_key.clone(),
                new_secret_key: new_sk.clone(),
                reason,
                keep_tofu,
            },
            d.keys.c(),
            d.keys.half(),
        )
        .unwrap();
    (out, new_sk)
}

fn this_id(d: &Device) -> String {
    d.session.this_device_id().unwrap()
}

// ---- tests ------------------------------------------------------------------------

/// End to end through the FFI only: A rotates, B sees the prompt after a
/// sync (the contract runs in the commit), stays read-only, refuses a
/// public session and a rotation of its own, fails to follow with a
/// failing half (nothing written), then follows with the master password
/// and gets the new Secret Key; its old session is `IdentityLeft`.
#[test]
fn two_devices_rotate_and_follow() {
    let mut server = Server::default();
    let mut a = first_device(&mut server);
    let b = pair_v2(&mut server, &a, "iPad de Camille");
    assert_eq!(
        b.session.lineage_status().unwrap().state,
        FfiLineageState::Current
    );
    let roster = a.session.roster().unwrap();
    assert_eq!(roster.len(), 2);
    assert!(roster.iter().all(|r| !r.tofu));
    assert_eq!(b.session.item_summaries().unwrap().len(), 1);

    let (out, new_sk) = rotate(&a, vec![], vec![]);
    assert_eq!(out.code.len(), 6);
    assert_eq!(out.auk.len(), 32);
    assert_eq!(a.session.lineage_status().unwrap().generation, 1);
    a.secret_key = new_sk.clone();
    push(&mut server, &a.path);

    // The commit of the fetch looks for the prompt.
    let commit = pull(&server, &b);
    let prompt = commit.prompt.clone().expect("prompt after the commit");
    assert_eq!(commit.quarantine, FfiQuarantineTick::NotQuarantined);
    assert_eq!(commit.lock, None);
    assert_eq!(prompt.kind, FfiPromptKind::Single);
    assert_eq!(prompt.code.as_deref(), Some(out.code.as_str()));
    assert_eq!(prompt.choices.len(), 1);
    let choice = prompt.choices[0].clone();
    assert_eq!(choice.choice, out.head);
    assert_eq!(choice.rotator_name, "Mac de Camille");
    assert!(choice.revoked_names.is_empty());
    assert!(choice.complete);
    assert!(!prompt.tofu_signer);
    assert_eq!(
        pending_rotation(b.path.clone()).unwrap(),
        Some(prompt.clone())
    );
    assert_eq!(b.session.pending_rotation().unwrap(), Some(prompt.clone()));

    // Read only until the user answers (R10).
    assert_eq!(
        b.session
            .save_item(login(&b.session, "Banque", "pw-banque"))
            .unwrap_err(),
        OnePassError::ReadOnly
    );
    assert_eq!(b.session.item_summaries().unwrap().len(), 1);
    assert_eq!(
        b.session.lineage_status().unwrap().state,
        FfiLineageState::Candidate
    );
    assert!(!lineage_status(b.path.clone()).unwrap().usable);
    // No rotation of its own meanwhile.
    let sk = generate_secret_key().unwrap();
    let r = b.session.rotate_keys(
        FfiRotateRequest {
            revoke: vec![],
            new_password: None,
            password: PASSWORD.into(),
            secret_key: b.secret_key.clone(),
            new_secret_key: sk,
            reason: FfiRotationReason::Rotate,
            keep_tofu: vec![],
        },
        b.keys.c(),
        b.keys.half(),
    );
    assert_eq!(r.err(), Some(OnePassError::RotationPending));
    // Spec 10.9: no public session outside `Current`.
    let pn = PairingNewcomer::new(
        "Ordinateur de l'hôtel".into(),
        FfiDeviceKind::Other,
        FfiDeviceMode::Public,
        now(),
    )
    .unwrap();
    let pa = PairingApprover::begin(pn.qr_text(), pn.hello(), now()).unwrap();
    pn.on_key_exchange(pa.key_exchange(), now()).unwrap();
    assert_eq!(
        pa.on_frame(pn.confirm().unwrap()).unwrap(),
        FfiPairingMessage::Confirmed
    );
    let item = b.session.item_summaries().unwrap()[0].clone();
    let refs = vec![FfiItemRef {
        vault_id: item.vault_id.clone(),
        item_id: item.id.clone(),
    }];
    assert_eq!(
        pa.seal_public_grant(b.session.clone(), refs.clone(), 15)
            .unwrap_err(),
        OnePassError::RotationPending
    );

    // A foreign half that fails: the follow fails, nothing written.
    b.keys.fail_decap.store(true, Ordering::SeqCst);
    let failed = follow_rotation(
        b.path.clone(),
        choice.choice.clone(),
        PASSWORD.into(),
        b.keys.c(),
        b.keys.half(),
    );
    assert!(failed.is_err());
    b.keys.fail_decap.store(false, Ordering::SeqCst);
    assert_eq!(
        pending_rotation(b.path.clone()).unwrap(),
        Some(prompt.clone())
    );
    assert_eq!(
        lineage_status(b.path.clone()).unwrap().state,
        FfiLineageState::Candidate
    );
    // A wrong password neither.
    assert_eq!(
        follow_rotation(
            b.path.clone(),
            choice.choice.clone(),
            "pas le bon".into(),
            b.keys.c(),
            b.keys.half(),
        )
        .err(),
        Some(OnePassError::WrongPassword)
    );

    let followed = follow_rotation(
        b.path.clone(),
        choice.choice.clone(),
        PASSWORD.into(),
        b.keys.c(),
        b.keys.half(),
    )
    .unwrap();
    assert_eq!(followed.secret_key, new_sk, "the new Secret Key, delivered");
    assert_eq!(followed.auk.len(), 32);
    assert!(!followed.reapply_needed);
    assert!(!followed.own_writes.alert);
    let s = &followed.session;
    assert_eq!(s.lineage_status().unwrap().generation, 1);
    assert_eq!(s.item_summaries().unwrap().len(), 1);
    // The old session is on the identity left: lock and unlock again.
    assert_eq!(b.session.vaults().unwrap_err(), OnePassError::IdentityLeft);
    // The new one writes; A reads it.
    s.save_item(login(s, "Banque", "pw-banque")).unwrap();
    push(&mut server, &b.path);
    pull(&server, &a);
    assert_eq!(a.session.item_summaries().unwrap().len(), 2);
    // Both sides open with the new Secret Key now.
    s.lock();
    unlock_with_password(b.path.clone(), PASSWORD.into(), new_sk.clone()).unwrap();
    // B is current again: public sessions are allowed.
    assert!(lineage_status(b.path.clone()).unwrap().usable);
}

/// A foreign half that fails to sign makes `rotate_keys` fail with no
/// record written: no lineage record queued, the head unchanged, and the
/// same call then succeeds with a working half.
#[test]
fn failing_half_writes_no_rotation() {
    let mut server = Server::default();
    let a = first_device(&mut server);
    assert!(
        open_sync_store(a.path.clone())
            .unwrap()
            .pending_changes()
            .unwrap()
            .is_empty()
    );
    a.keys.fail_sign.store(true, Ordering::SeqCst);
    let r = a.session.rotate_keys(
        FfiRotateRequest {
            revoke: vec![],
            new_password: None,
            password: PASSWORD.into(),
            secret_key: a.secret_key.clone(),
            new_secret_key: generate_secret_key().unwrap(),
            reason: FfiRotationReason::Rotate,
            keep_tofu: vec![],
        },
        a.keys.c(),
        a.keys.half(),
    );
    assert_eq!(r.err(), Some(OnePassError::Crypto));
    let status = a.session.lineage_status().unwrap();
    assert_eq!(status.state, FfiLineageState::Current);
    assert_eq!(status.generation, 0);
    assert!(
        open_sync_store(a.path.clone())
            .unwrap()
            .pending_changes()
            .unwrap()
            .is_empty()
    );
    // Keys that are not this device's: refused, nothing written either.
    let other = Keys::new();
    let r = a.session.rotate_keys(
        FfiRotateRequest {
            revoke: vec![],
            new_password: None,
            password: PASSWORD.into(),
            secret_key: a.secret_key.clone(),
            new_secret_key: generate_secret_key().unwrap(),
            reason: FfiRotationReason::Rotate,
            keep_tofu: vec![],
        },
        other.c(),
        other.half(),
    );
    assert!(matches!(r.err(), Some(OnePassError::Validation { .. })));
    a.keys.fail_sign.store(false, Ordering::SeqCst);
    rotate(&a, vec![], vec![]);
    assert_eq!(a.session.lineage_status().unwrap().generation, 1);
    assert!(
        !open_sync_store(a.path.clone())
            .unwrap()
            .pending_changes()
            .unwrap()
            .is_empty()
    );
}

/// A removes B by rotation. B's fetch (the plain `commit_remote` too)
/// records the quarantine; B is locked (`Quarantined`), and the clock
/// erases it only once 7 days have passed since `since`.
#[test]
fn quarantine_erases_only_after_seven_days() {
    let mut server = Server::default();
    let a = first_device(&mut server);
    let b = pair_v2(&mut server, &a, "iPad de Camille");
    let b_id = this_id(&b);
    let draft = login(&b.session, "Banque", "pw");
    // Spec 10.1: removing a v2 device is a rotation.
    assert!(a.session.revoke_device(b_id.clone()).is_err());
    assert!(a.session.lineage_status().unwrap().removes_by_rotation);
    rotate(&a, vec![b_id.clone()], vec![]);
    let listed = a.session.devices().unwrap();
    let gone = listed.iter().find(|d| d.id == b_id).unwrap();
    assert!(gone.revoked);
    assert_ne!(gone.revoked_at, Some(0), "an unknown date is hidden");
    push(&mut server, &a.path);

    // The plain commit runs the contract with the system clock.
    let h = open_sync_store(b.path.clone()).unwrap();
    for r in &server.rows[b.cursor.get()..] {
        h.stage_remote(r.clone()).unwrap();
    }
    let before = now_u();
    h.commit_remote().unwrap();
    let FfiLineageState::Quarantined { since, erase_at } =
        lineage_status(b.path.clone()).unwrap().state
    else {
        panic!("quarantined at the commit");
    };
    assert!(since >= before && since <= now_u());
    assert_eq!(erase_at, since + WEEK);
    assert!(matches!(
        lineage_lock(b.path.clone()).unwrap(),
        Some(FfiLineageLock::Quarantine { .. })
    ));
    assert_eq!(pending_rotation(b.path.clone()).unwrap(), None);
    assert_eq!(b.session.vaults().unwrap_err(), OnePassError::Quarantined);
    assert_eq!(
        b.session.save_item(draft).unwrap_err(),
        OnePassError::Quarantined
    );

    // Not before the 7 days, whatever the clock says before them.
    assert_eq!(
        quarantine_tick(b.path.clone(), since + WEEK - 1).unwrap(),
        FfiQuarantineTick::Waiting { erase_at }
    );
    assert_eq!(
        quarantine_tick(b.path.clone(), since - 3600).unwrap(),
        FfiQuarantineTick::Waiting { erase_at }
    );
    assert_eq!(store_state(b.path.clone()).unwrap(), FfiStoreState::Account);
    // A locked device fetches nothing more; `since` stays.
    let h = open_sync_store(b.path.clone()).unwrap();
    match h.stage_remote(server.rows[0].clone()) {
        Err(e) => assert_eq!(e, OnePassError::Quarantined),
        Ok(()) => assert_eq!(
            h.commit_remote_checked(since + 60).unwrap().quarantine,
            FfiQuarantineTick::Waiting { erase_at }
        ),
    }
    assert_eq!(
        quarantine_tick(b.path.clone(), since + WEEK).unwrap(),
        FfiQuarantineTick::Erased
    );
    assert_eq!(store_state(b.path.clone()).unwrap(), FfiStoreState::Empty);
}

/// "Ce n'était pas moi" on the prompt: the record rejected, the device
/// writes again.
#[test]
fn reject_lets_the_device_write() {
    let mut server = Server::default();
    let mut a = first_device(&mut server);
    let b = pair_v2(&mut server, &a, "iPad de Camille");
    a.secret_key = rotate(&a, vec![], vec![]).1;
    push(&mut server, &a.path);
    let prompt = pull(&server, &b).prompt.unwrap();
    // Not offered: refused.
    assert!(reject_rotation(b.path.clone(), "00".repeat(32), false).is_err());
    reject_rotation(b.path.clone(), prompt.choices[0].choice.clone(), false).unwrap();
    assert_eq!(pending_rotation(b.path.clone()).unwrap(), None);
    assert_eq!(b.session.pending_rotation().unwrap(), None);
    b.session
        .save_item(login(&b.session, "Banque", "pw-banque"))
        .unwrap();
}

/// "Ce n'était pas moi" with the password on a quarantine: the signer
/// excluded, the erase cancelled, the session opened.
#[test]
fn not_me_cancels_the_erase() {
    let mut server = Server::default();
    let a = first_device(&mut server);
    let b = pair_v2(&mut server, &a, "iPad de Camille");
    let b_id = this_id(&b);
    rotate(&a, vec![b_id], vec![]);
    push(&mut server, &a.path);
    let commit = pull(&server, &b);
    assert!(matches!(
        commit.quarantine,
        FfiQuarantineTick::Waiting { .. }
    ));
    assert!(
        quarantine_resolve(
            b.path.clone(),
            FfiQuarantineChoice::NotMe {
                password: "pas le bon".into(),
                secret_key: b.secret_key.clone(),
            },
        )
        .is_err()
    );
    let s = quarantine_resolve(
        b.path.clone(),
        FfiQuarantineChoice::NotMe {
            password: PASSWORD.into(),
            secret_key: b.secret_key.clone(),
        },
    )
    .unwrap()
    .expect("a session");
    assert_eq!(
        quarantine_tick(b.path.clone(), now_u() + 2 * WEEK).unwrap(),
        FfiQuarantineTick::NotQuarantined
    );
    assert_eq!(s.item_summaries().unwrap().len(), 1);
}

/// Two legacy devices migrate through the FFI; A's rotation lists B for an
/// explicit yes (`Tofu`). Without it B is left out: `Orphaned` (it reads,
/// it never writes); an Emergency Kit of before the rotation is
/// `OutdatedKit`.
#[test]
fn migration_tofu_orphaned_and_outdated_kit() {
    let mut server = Server::default();
    let (a, b) = legacy_pair(&mut server);
    let old_sk = a.secret_key.clone();
    let b_id = this_id(&b);
    let roster = a.session.roster().unwrap();
    let rb = roster.iter().find(|r| r.id == b_id).expect("B pinned");
    assert!(rb.tofu, "trusted on first use");
    assert_eq!(
        a.session.unmigrated_devices().unwrap(),
        Vec::<String>::new()
    );

    // Not kept: B leaves the keys.
    let (_, new_sk) = rotate(&a, vec![], vec![]);
    push(&mut server, &a.path);
    let commit = pull(&server, &b);
    assert!(matches!(commit.lock, Some(FfiLineageLock::Orphaned { .. })));
    assert_eq!(commit.prompt, None);
    assert_eq!(
        lineage_status(b.path.clone()).unwrap().state,
        FfiLineageState::Orphaned
    );
    assert_eq!(b.session.item_summaries().unwrap().len(), 1, "it reads");
    assert_eq!(
        b.session
            .save_item(login(&b.session, "Banque", "pw"))
            .unwrap_err(),
        OnePassError::Orphaned
    );

    // Its exit: a re-pair from A under its own id (spec 7.4), applied as
    // a follow; A grants it again without listing it twice.
    let n = PairingNewcomer::repair(
        b.session.clone(),
        "iPad de Camille".into(),
        FfiDeviceKind::Tablet,
        FfiDeviceMode::Personal,
        now(),
    )
    .unwrap();
    assert_eq!(n.device_id(), b_id);
    let ap = PairingApprover::begin(n.qr_text(), n.hello(), now()).unwrap();
    assert!(ap.is_known_device(a.session.clone()).unwrap());
    n.on_key_exchange(ap.key_exchange(), now()).unwrap();
    let f = n.confirm_with_key(b.keys.c(), b.keys.half()).unwrap();
    assert_eq!(ap.on_frame(f).unwrap(), FfiPairingMessage::Confirmed);
    let devices_before = a.session.devices().unwrap().len();
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            new_sk.clone(),
            FfiDeviceMode::Personal,
            true,
        )
        .unwrap();
    n.open(frame).unwrap();
    let back = n
        .repair_with_grant(
            b.session.clone(),
            PASSWORD.into(),
            b.keys.c(),
            b.keys.half(),
        )
        .unwrap();
    assert_eq!(back.secret_key, new_sk);
    assert_eq!(b.session.vaults().err(), Some(OnePassError::Locked));
    let ack = n.seal_key_ack(b.keys.c(), b.keys.half()).unwrap();
    assert_eq!(ap.on_frame(ack).unwrap(), FfiPairingMessage::Ack);
    ap.introduce(a.session.clone(), a.keys.c(), a.keys.half())
        .unwrap();
    assert_eq!(a.session.devices().unwrap().len(), devices_before);
    assert_eq!(
        back.session.lineage_status().unwrap().state,
        FfiLineageState::Current
    );
    back.session
        .save_item(login(&back.session, "Banque", "pw-banque"))
        .unwrap();

    // A new device with the old kit: refused, nothing restored.
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let cursor = Cell::new(0);
    pull_at(&server, &path, &cursor, now_u());
    let k = Keys::new();
    let r = restore_from_kit(
        path.clone(),
        PASSWORD.into(),
        old_sk,
        k.c(),
        k.half(),
        "iPhone de Camille".into(),
        FfiDeviceKind::Phone,
        FfiDeviceMode::Personal,
    );
    match r.err() {
        Some(OnePassError::OutdatedKit { rotator, at }) => {
            assert_eq!(rotator, "un autre appareil");
            assert!(at > 0);
        }
        other => panic!("expected OutdatedKit, got {other:?}"),
    }
    // The latest kit restores; the device asks to be trusted.
    let s = restore_from_kit(
        path.clone(),
        PASSWORD.into(),
        new_sk,
        k.c(),
        k.half(),
        "iPhone de Camille".into(),
        FfiDeviceKind::Phone,
        FfiDeviceMode::Personal,
    )
    .unwrap();
    assert!(s.awaiting_pin().unwrap());
    push(&mut server, &path);
    pull(&server, &a);
    let asking = a.session.kit_restored_devices().unwrap();
    assert_eq!(asking.len(), 1);
    assert_eq!(asking[0].name, "iPhone de Camille");
    assert!(!asking[0].rotated);
    a.session
        .accept_kit_restored(asking[0].id.clone(), a.keys.c(), a.keys.half())
        .unwrap();
    assert!(
        a.session
            .roster()
            .unwrap()
            .iter()
            .any(|r| r.id == asking[0].id)
    );
}

/// Kept on purpose: the `Tofu` device gets the prompt, with the warning
/// that its rotator was not verified since the update (O7).
#[test]
fn kept_tofu_device_follows_with_warning() {
    let mut server = Server::default();
    let (a, b) = legacy_pair(&mut server);
    let b_id = this_id(&b);
    let (_, new_sk) = rotate(&a, vec![], vec![b_id]);
    push(&mut server, &a.path);
    let prompt = pull(&server, &b).prompt.expect("prompt");
    assert!(prompt.tofu_signer);
    let f = follow_rotation(
        b.path.clone(),
        prompt.choices[0].choice.clone(),
        PASSWORD.into(),
        b.keys.c(),
        b.keys.half(),
    )
    .unwrap();
    assert_eq!(f.secret_key, new_sk);
}

// ---- legacy devices -----------------------------------------------------------------

/// A legacy account (no device keys) on A, a legacy pairing of B, then
/// both migrate on their first unlock after the update (spec 15): A makes
/// the genesis, B joins it with a legacy intro; A pins B as `Tofu`.
fn legacy_pair(server: &mut Server) -> (Device, Device) {
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let created = create_account_with_kdf(path.clone(), PASSWORD.into(), FAST).unwrap();
    created
        .session
        .register_this_device(
            "Mac de Camille".into(),
            FfiDeviceKind::Mac,
            FfiDeviceMode::Personal,
        )
        .unwrap();
    created
        .session
        .save_item(login(
            &created.session,
            "Messagerie exemple.fr",
            "pw-atlas-1",
        ))
        .unwrap();
    push(server, &path);
    let a = Device {
        _dir: dir,
        path,
        session: created.session,
        secret_key: created.secret_key,
        keys: Keys::new(),
        cursor: Cell::new(0),
    };
    pull(server, &a);

    let n = PairingNewcomer::new(
        "iPad de Camille".into(),
        FfiDeviceKind::Tablet,
        FfiDeviceMode::Personal,
        now(),
    )
    .unwrap();
    let ap = PairingApprover::begin(n.qr_text(), n.hello(), now()).unwrap();
    n.on_key_exchange(ap.key_exchange(), now()).unwrap();
    assert_eq!(
        ap.on_frame(n.confirm().unwrap()).unwrap(),
        FfiPairingMessage::Confirmed
    );
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
        )
        .unwrap();
    n.open(frame).unwrap();
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let u = n.import_snapshot(path.clone(), PASSWORD.into()).unwrap();
    push(server, &a.path);
    let b = Device {
        _dir: dir,
        path,
        session: u.session,
        secret_key: n.take_secret_key().unwrap(),
        keys: Keys::new(),
        cursor: Cell::new(0),
    };
    pull(server, &b);

    assert_eq!(
        a.session.lineage_status().unwrap().state,
        FfiLineageState::Legacy
    );
    assert!(matches!(
        a.session.migrate_to_v2(a.keys.c(), a.keys.half()).unwrap(),
        FfiMigration::Genesis { .. }
    ));
    push(server, &a.path);
    pull(server, &b);
    assert!(matches!(
        b.session.migrate_to_v2(b.keys.c(), b.keys.half()).unwrap(),
        FfiMigration::Joined { .. }
    ));
    assert_eq!(
        b.session.migrate_to_v2(b.keys.c(), b.keys.half()).unwrap(),
        FfiMigration::Already
    );
    push(server, &b.path);
    pull(server, &a);
    // The next look at the lineage pins B's legacy intro.
    a.session.pending_rotation().unwrap();
    (a, b)
}

/// "Vérifier mes appareils" (spec 15 step 4): the proof of possession of
/// B's device key over the pairing transcript makes it `Verified` on A; a
/// rotation then keeps it without asking.
#[test]
fn verified_device_needs_no_keep() {
    use onepass_core::device_keys::{DeviceKeys, sign_pop};
    let mut server = Server::default();
    let (a, b) = legacy_pair(&mut server);
    let b_id = this_id(&b);
    let public = device_public(b.keys.c(), b.keys.half(), b_id.clone()).unwrap();
    let keys = DeviceKeys::new(
        &b.keys.classical,
        Box::new(SoftwarePqHalf::from_bytes(&b.keys.pq).unwrap()),
    )
    .unwrap();
    let decoded = onepass_core::device_keys::DevicePublic::decode(&public).unwrap();
    let pop = postcard::to_allocvec(&sign_pop(&keys, b"transcript", &decoded).unwrap()).unwrap();
    assert!(
        a.session
            .verify_device(public.clone(), b"another".to_vec(), pop.clone())
            .is_err()
    );
    assert!(
        a.session
            .roster()
            .unwrap()
            .iter()
            .any(|r| r.id == b_id && r.tofu)
    );
    a.session
        .verify_device(public, b"transcript".to_vec(), pop)
        .unwrap();
    assert!(
        a.session
            .roster()
            .unwrap()
            .iter()
            .any(|r| r.id == b_id && !r.tofu)
    );
    rotate(&a, vec![], vec![]);
    push(&mut server, &a.path);
    assert!(pull(&server, &b).prompt.is_some(), "kept, not orphaned");
}

/// Honest concurrency (spec 8.5): A and B rotate at the same time. The
/// device whose rotation loses gets a `Switch` prompt and follows from its
/// open session (`Session::follow_switch`), which is consumed.
#[test]
fn concurrent_rotations_switch_from_the_session() {
    let mut server = Server::default();
    let a = first_device(&mut server);
    let b = pair_v2(&mut server, &a, "iPad de Camille");
    let (out_a, sk_a) = rotate(&a, vec![], vec![]);
    let (out_b, sk_b) = rotate(&b, vec![], vec![]);
    assert_ne!(out_a.head, out_b.head);
    push(&mut server, &a.path);
    let (loser, winner_sk) = match pull(&server, &b).prompt {
        Some(p) => {
            assert!(matches!(
                p.kind,
                FfiPromptKind::Switch | FfiPromptKind::Reapply
            ));
            (&b, sk_a)
        }
        None => {
            push(&mut server, &b.path);
            let p = pull(&server, &a).prompt.expect("A lost");
            assert!(matches!(
                p.kind,
                FfiPromptKind::Switch | FfiPromptKind::Reapply
            ));
            (&a, sk_b)
        }
    };
    let prompt = loser.session.pending_rotation().unwrap().expect("switch");
    let summary = loser.session.item_summaries().unwrap()[0].clone();
    let item = loser.session.item(summary.vault_id, summary.id).unwrap();
    assert_eq!(
        loser.session.save_item(item).unwrap_err(),
        OnePassError::ReadOnly
    );
    let f = loser
        .session
        .follow_switch(
            prompt.choices[0].choice.clone(),
            PASSWORD.into(),
            loser.keys.c(),
            loser.keys.half(),
        )
        .unwrap();
    assert_eq!(f.secret_key, winner_sk);
    assert_eq!(loser.session.vaults().err(), Some(OnePassError::Locked));
    assert_eq!(
        f.session.lineage_status().unwrap().state,
        FfiLineageState::Current
    );
}
