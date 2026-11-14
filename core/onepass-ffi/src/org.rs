//! Organization (OnePass Business) types of the FFI: roles, members, the
//! pinned state the apps show, the fingerprint words and the join link.
//! Swift gets display values only: never org record bytes, org secrets or
//! the owner keyset.

mod invite;
mod pinstore;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use onepass_core::generator::Wordlist;
use onepass_core::lineage::LineageRecord;
use onepass_core::org::{
    MemberRef, MemberState, ORG_FORMAT, OrgGenesisBody, OrgId, OrgKeyset, OrgPin, OrgSecrets,
    PinSource, Role, RoleSet, dns_txt_value, fingerprint_words, founding_roster, parse_dns_txt,
    pin_org, seal_org_keyset, sign_org_genesis, sign_roster, verify_org_genesis,
};
use onepass_core::repo::ManagedGenesis;
use onepass_core::store::{RecordKind, RecordStore};
use onepass_core::sync::SyncStore;
use onepass_core::{Id, IntegrityError};
use onepass_mailbox::{MailboxApi, MailboxClient, OrgStore, OrgStoreApi};
use zeroize::Zeroizing;

use crate::convert::{bytes_hex, hex_bytes, id_hex, parse_id};
use crate::devices::{FfiDeviceKind, FfiDeviceMode};
use crate::error::{OnePassError, invalid};
use crate::mailbox::{FfiMailboxEndpoint, LABEL, credential, fresh_credential, mailbox_id};
use crate::rotation::{FfiPqDeviceHalf, device_keys};
use crate::session::Session;
use crate::types::{FfiCreatedAccount, FfiKdfParams};
use pinstore::{load_pin, pin_lock, save_pin};

pub use invite::{org_invite_encode, org_invite_parse};

/// A role of an organization member (a member holds a set of them).
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FfiOrgRole {
    Owner,
    Admin,
    UserManager,
    PolicyManager,
    Auditor,
    RecoveryOfficer,
    Provisioner,
}

/// Where a member stands in the roster.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum FfiMemberState {
    Invited,
    Active,
    Suspended,
    /// `at`: Unix seconds. `by`: the account id (32 hex) that removed it.
    Removed {
        at: i64,
        by: String,
    },
}

/// How this device pinned the organization.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiPinSource {
    Mdm,
    Dns,
    Tofu { verified: bool },
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgDevice {
    /// 64 hex.
    pub fingerprint: String,
    pub name: Option<String>,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgMember {
    /// 32 lowercase hex.
    pub account_id: String,
    pub display_name: Option<String>,
    pub roles: Vec<FfiOrgRole>,
    pub state: FfiMemberState,
    pub devices: Vec<FfiOrgDevice>,
    /// In an earlier owner set of the lineage, not in the head.
    pub former_owner: bool,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgState {
    pub org_id: String,
    pub name: String,
    pub fingerprint: Vec<u8>,
    /// 4 groups of 5 words.
    pub fingerprint_words: Vec<Vec<String>>,
    /// `v=op1; org=...`, the DNS TXT value.
    pub dns_value: String,
    pub source: FfiPinSource,
    pub lineage_generation: u64,
    /// 0 when no roster is pinned yet.
    pub roster_seq: u64,
    /// 32 lowercase hex account ids.
    pub owners: Vec<String>,
    pub members: Vec<FfiOrgMember>,
}

/// The content of a join link (see `invite`).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgInvite {
    pub server_url: String,
    /// 32 hex.
    pub mailbox_id: String,
    /// 32 hex.
    pub org_id: String,
    /// 32 hex: the Invited member's account id the inviter chose.
    pub account_id: String,
    pub fingerprint: Vec<u8>,
    /// 32 bytes.
    pub nonce: Vec<u8>,
    /// 32 bytes: the seed of the invite credential.
    pub credential_seed: Vec<u8>,
    /// 32 bytes: the one-use `managed` mailbox token.
    pub member_token: Vec<u8>,
    pub domain: Option<String>,
}

fn fpr_array(fingerprint: &[u8]) -> Result<[u8; 32], OnePassError> {
    fingerprint
        .try_into()
        .map_err(|_| invalid("organisation fingerprint"))
}

fn words(fpr: &[u8; 32]) -> Vec<Vec<String>> {
    fingerprint_words(fpr, Wordlist::EffEnglish)
        .into_iter()
        .map(|g| g.into_iter().collect())
        .collect()
}

/// The 4 x 5 words of a fingerprint, always the EFF English list (the
/// words are read aloud and compared across devices, whatever their locale).
#[uniffi::export]
pub fn org_fingerprint_words(fingerprint: Vec<u8>) -> Result<Vec<Vec<String>>, OnePassError> {
    Ok(words(&fpr_array(&fingerprint)?))
}

/// The fingerprint of a DNS TXT value (`v=op1; org=<base32>`).
#[uniffi::export]
pub fn org_parse_dns_txt(text: String) -> Result<Vec<u8>, OnePassError> {
    Ok(parse_dns_txt(&text)?.to_vec())
}

/// The fingerprint of its bare base32 text (52 characters, any case): the
/// MDM `org_fpr` value.
#[uniffi::export]
pub fn org_parse_fingerprint(text: String) -> Result<Vec<u8>, OnePassError> {
    Ok(parse_fingerprint(&text)?.to_vec())
}

pub(crate) fn parse_fingerprint(text: &str) -> Result<[u8; 32], OnePassError> {
    let text = text.trim_ascii();
    if text.len() != 52 {
        return Err(invalid("organisation fingerprint"));
    }
    data_encoding::BASE32_NOPAD
        .decode(text.to_ascii_uppercase().as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("organisation fingerprint"))
}

// ---- create, open, pin and verify ---------------------------------------------------

fn lock<T: ?Sized>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn org_id_of(hex: &str) -> Result<[u8; 16], OnePassError> {
    if hex.len() != 32 {
        return Err(invalid("organisation id"));
    }
    hex_bytes(hex)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("organisation id"))
}

fn integrity(e: IntegrityError) -> OnePassError {
    onepass_core::Error::Integrity(e).into()
}

const ROLES: [(Role, FfiOrgRole); 7] = [
    (Role::Owner, FfiOrgRole::Owner),
    (Role::Admin, FfiOrgRole::Admin),
    (Role::UserManager, FfiOrgRole::UserManager),
    (Role::PolicyManager, FfiOrgRole::PolicyManager),
    (Role::Auditor, FfiOrgRole::Auditor),
    (Role::RecoveryOfficer, FfiOrgRole::RecoveryOfficer),
    (Role::Provisioner, FfiOrgRole::Provisioner),
];

fn roles_of(set: RoleSet) -> Vec<FfiOrgRole> {
    ROLES
        .iter()
        .filter(|(r, _)| set.contains(*r))
        .map(|(_, f)| *f)
        .collect()
}

impl From<&MemberState> for FfiMemberState {
    fn from(s: &MemberState) -> Self {
        match s {
            MemberState::Invited => FfiMemberState::Invited,
            MemberState::Active => FfiMemberState::Active,
            MemberState::Suspended => FfiMemberState::Suspended,
            MemberState::Removed { at, by } => FfiMemberState::Removed {
                at: *at,
                by: id_hex(*by),
            },
        }
    }
}

impl From<PinSource> for FfiPinSource {
    fn from(s: PinSource) -> Self {
        match s {
            PinSource::Mdm => FfiPinSource::Mdm,
            PinSource::Dns => FfiPinSource::Dns,
            PinSource::Tofu { verified } => FfiPinSource::Tofu { verified },
        }
    }
}

impl From<FfiPinSource> for PinSource {
    fn from(s: FfiPinSource) -> Self {
        match s {
            FfiPinSource::Mdm => PinSource::Mdm,
            FfiPinSource::Dns => PinSource::Dns,
            FfiPinSource::Tofu { verified } => PinSource::Tofu { verified },
        }
    }
}

/// What the apps show of a pin: built from the local pinned state only.
/// `names`: display names by account id (from verified join requests,
/// Task 3); a member without one shows none (the app says "You" for its own
/// account).
fn view(pin: &OrgPin, names: &HashMap<[u8; 16], String>) -> FfiOrgState {
    let lineage = pin.lineage();
    let head = pin.head();
    let fpr = pin.fingerprint();
    let owns = |owners: &[MemberRef], id: Id| owners.iter().any(|o| o.account_id == id);
    let earlier = &lineage.heads[..lineage.heads.len() - 1];
    let members = pin
        .roster()
        .map(|r| {
            r.members
                .iter()
                .map(|m| FfiOrgMember {
                    account_id: id_hex(m.account_id),
                    display_name: names.get(&m.account_id.0).cloned(),
                    roles: roles_of(m.roles),
                    state: (&m.state).into(),
                    devices: m
                        .devices
                        .iter()
                        .map(|d| FfiOrgDevice {
                            fingerprint: bytes_hex(d),
                            name: None,
                        })
                        .collect(),
                    former_owner: !owns(&head.owners, m.account_id)
                        && earlier.iter().any(|h| owns(&h.owners, m.account_id)),
                })
                .collect()
        })
        .unwrap_or_default();
    FfiOrgState {
        org_id: bytes_hex(&lineage.org_id.0),
        name: lineage.name.clone(),
        fingerprint: fpr.to_vec(),
        fingerprint_words: words(&fpr),
        dns_value: dns_txt_value(&fpr),
        source: pin.source().into(),
        lineage_generation: head.generation,
        roster_seq: pin.roster_seq().unwrap_or(0),
        owners: head.owners.iter().map(|o| id_hex(o.account_id)).collect(),
        members,
    }
}

/// The rosters a pin moves forward with: from the pinned seq (seq 1 for a
/// first pin) to the newest the server names. The pinned seq itself is
/// asked again, so a server that withholds the newest or replays an older
/// roster answers a list topping out below the pin: `OrgRosterRollback` in
/// the core, never a silent "nothing new". A newest below the pinned seq
/// goes to the core alone (rollback, or fork if it is not the pinned chain).
fn rosters_since(
    store: &mut dyn OrgStoreApi,
    pinned: Option<u64>,
) -> Result<Vec<(u64, Vec<u8>)>, OnePassError> {
    let start = pinned.unwrap_or(1).max(1);
    let Some((latest, newest)) = store.latest_roster()? else {
        return match pinned {
            Some(_) => Err(integrity(IntegrityError::OrgRosterRollback)),
            None => Ok(Vec::new()),
        };
    };
    if latest < start {
        return Ok(vec![(latest, newest)]);
    }
    let mut out = Vec::new();
    for seq in start..latest {
        // A hole below the newest the server named: it withholds a roster
        // the chain needs, a rollback of what it announced. Stops at the
        // first one.
        let bytes = store
            .roster(seq)?
            .ok_or_else(|| integrity(IntegrityError::OrgRosterRollback))?;
        out.push((seq, bytes));
    }
    out.push((latest, newest));
    Ok(out)
}

/// `pin` moved forward by `lineage` (from its head generation on) and the
/// rosters from its seq on. Nothing is written here.
fn advance(
    store: &mut dyn OrgStoreApi,
    pin: &OrgPin,
    lineage: &[(u64, Vec<u8>)],
) -> Result<OrgPin, OnePassError> {
    let rosters = rosters_since(store, pin.roster_seq())?;
    Ok(pin.advance(lineage, &rosters)?)
}

/// What `OrgDraft::publish` returns. `credential_seed`: the seed of the
/// org mailbox's managing credential, for the app's keychain (never kept
/// on the Rust side).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgCreated {
    /// 32 hex.
    pub mailbox_id: String,
    pub credential_seed: Vec<u8>,
    pub state: FfiOrgState,
}

/// A new organisation before it exists anywhere: its id and its secrets
/// (identity and audit keys), drawn once. The app makes the creator's
/// managed account with `org_id()` (`create_managed_account(.., org_id,
/// None)`), then `publish`es with that account's session. The fingerprint
/// commits to the whole genesis (name, owners, creation time), so it is
/// known only once published (`FfiOrgCreated.state`).
#[derive(uniffi::Object)]
pub struct OrgDraft {
    org_id: OrgId,
    stage: Mutex<Stage>,
}

/// Where a draft stands. The secrets live until the org mailbox exists;
/// from then on the signed records and the mailbox client wait in
/// `Created` until every write and the pin are done.
enum Stage {
    Fresh(OrgSecrets),
    Created(Box<Pending>),
    Used,
}

/// A publish whose org mailbox exists (the one-use invite is spent) but
/// whose records or pin are not all written yet.
struct Pending {
    client: Box<dyn MailboxApi>,
    credential_seed: Zeroizing<Vec<u8>>,
    mailbox_id: [u8; 16],
    genesis: Vec<u8>,
    roster: Vec<u8>,
    owner_account: [u8; 16],
    sealed_keyset: Vec<u8>,
    pin: OrgPin,
}

/// What a publish writes, signed before the mailbox is created.
struct Signed {
    genesis: Vec<u8>,
    roster: Vec<u8>,
    owner_account: [u8; 16],
    sealed_keyset: Vec<u8>,
    pin: OrgPin,
}

/// A mailbox client holding a fresh credential, and that credential's seed.
type Connect<'a> =
    Box<dyn FnOnce() -> Result<(Box<dyn MailboxApi>, Zeroizing<Vec<u8>>), OnePassError> + 'a>;

#[uniffi::export]
impl OrgDraft {
    #[uniffi::constructor]
    pub fn new() -> Result<Arc<Self>, OnePassError> {
        Ok(Arc::new(OrgDraft {
            org_id: OrgId::generate()?,
            stage: Mutex::new(Stage::Fresh(OrgSecrets::generate()?)),
        }))
    }

    /// 32 lowercase hex.
    pub fn org_id(&self) -> String {
        bytes_hex(&self.org_id.0)
    }

    /// Creates the org mailbox on `endpoint` from the one-use org-plan
    /// `server_invite` with a fresh credential, then writes the genesis
    /// (generation 0, this account its single owner with this device), the
    /// founding roster (seq 1, this account Active with `Owner`) and the
    /// owner keyset sealed to this account, and pins the org in
    /// `state_dir` as `Tofu { verified: true }` (the creator vouches for its
    /// own genesis). `session` must be a managed account of this org
    /// (`Validation { field: "org" }`), unlocked, opened with these device
    /// keys.
    ///
    /// A failure before the mailbox exists leaves the draft as it was. A
    /// failure after (a write or the pin) keeps the mailbox, its credential
    /// and the signed records in the draft: calling `publish` again resumes
    /// the remaining writes and the pin on that mailbox (the same bytes
    /// again are accepted), whatever the other arguments, and never spends
    /// another invite. Once a publish has finished, a further call is
    /// `InvalidInput("draft used")`.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &self,
        endpoint: FfiMailboxEndpoint,
        server_invite: String,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        name: String,
        state_dir: String,
        now: i64,
    ) -> Result<FfiOrgCreated, OnePassError> {
        let classical = Zeroizing::new(classical);
        let connect: Connect<'_> = Box::new(move || {
            let credential = fresh_credential()?;
            let seed = credential.seed();
            let client: Box<dyn MailboxApi> =
                Box::new(MailboxClient::new(endpoint.into(), credential)?);
            Ok((client, seed))
        });
        self.publish_on(
            connect,
            &server_invite,
            &session,
            &classical,
            pq,
            name,
            Path::new(&state_dir),
            now,
        )
    }
}

impl OrgDraft {
    /// `publish` over the mailbox client `connect` makes (called only when
    /// the mailbox is still to be created).
    #[allow(clippy::too_many_arguments)]
    fn publish_on(
        &self,
        connect: Connect<'_>,
        server_invite: &str,
        session: &Session,
        classical: &[u8],
        pq: Arc<dyn FfiPqDeviceHalf>,
        name: String,
        state_dir: &Path,
        now: i64,
    ) -> Result<FfiOrgCreated, OnePassError> {
        // Held for the whole call: one publish at a time per draft.
        let mut stage = lock(&self.stage);
        let pending = match std::mem::replace(&mut *stage, Stage::Used) {
            Stage::Used => return Err(invalid("draft used")),
            Stage::Created(p) => p,
            Stage::Fresh(secrets) => {
                let keyset = OrgKeyset {
                    org_id: self.org_id,
                    secrets,
                };
                let created = self
                    .sign(&keyset, session, classical, pq, name, now)
                    .and_then(|signed| {
                        let (mut client, credential_seed) = connect()?;
                        let created = client.create(Some(server_invite.as_bytes()), LABEL)?;
                        Ok((signed, client, credential_seed, created.mailbox_id))
                    });
                match created {
                    // Nothing exists anywhere yet: the draft stays fresh.
                    Err(e) => {
                        *stage = Stage::Fresh(keyset.secrets);
                        return Err(e);
                    }
                    Ok((signed, client, credential_seed, mailbox_id)) => Box::new(Pending {
                        client,
                        credential_seed,
                        mailbox_id,
                        genesis: signed.genesis,
                        roster: signed.roster,
                        owner_account: signed.owner_account,
                        sealed_keyset: signed.sealed_keyset,
                        pin: signed.pin,
                    }),
                }
            }
        };
        match self.finish(pending, state_dir) {
            Ok(created) => Ok(created),
            Err((pending, e)) => {
                *stage = Stage::Created(pending);
                Err(e)
            }
        }
    }

    /// The genesis, the founding roster, the sealed keyset and the pin,
    /// signed by this device for the managed account of `session`.
    fn sign(
        &self,
        keyset: &OrgKeyset,
        session: &Session,
        classical: &[u8],
        pq: Arc<dyn FfiPqDeviceHalf>,
        name: String,
        now: i64,
    ) -> Result<Signed, OnePassError> {
        let keys = device_keys(classical, pq)?;
        let (owner, me) = session.with(|repo| {
            if repo.genesis_org()? != Some(self.org_id) {
                return Err(OnePassError::Validation {
                    field: "org".into(),
                    reason: "not a managed account of this organisation".into(),
                });
            }
            let me = repo
                .store()
                .trust_state()?
                .ok_or_else(|| invalid("device keys"))?
                .me;
            let p = &repo.account().params;
            let owner = MemberRef {
                account_id: p.account_id,
                account_identity_pub: p.identity_pub.clone(),
                account_kem_pub: p.kem_pub.clone(),
                devices: vec![me.fingerprint()],
            };
            Ok((owner, me))
        })?;
        if keys.public(me.device_id)? != me {
            return Err(invalid("device keys"));
        }
        let public = keyset.secrets.public(self.org_id)?;
        let body = OrgGenesisBody {
            format: ORG_FORMAT,
            org_id: self.org_id,
            name,
            org_identity_pub: public.identity_pub,
            audit_kem_pub: public.audit_kem_pub,
            owners: vec![owner.clone()],
            created_at: now,
        };
        let genesis = sign_org_genesis(body, &keyset.secrets.identity, &[(&me, &keys)])?;
        let lineage = verify_org_genesis(&genesis)?;
        let roster = sign_roster(founding_roster(&lineage)?, &me, &keys)?;
        let sealed = seal_org_keyset(keyset, owner.account_id, &owner.account_kem_pub)?;
        let (genesis, roster) = (genesis.encode(), roster.encode());
        // The pin goes through the same checks as any other device's.
        let pin = pin_org(PinSource::Tofu { verified: false }, None, &genesis)?
            .advance(&[(0, genesis.clone())], &[(1, roster.clone())])?;
        let pin = pin.confirm_tofu(&pin.fingerprint())?;
        Ok(Signed {
            genesis,
            roster,
            owner_account: owner.account_id.0,
            sealed_keyset: sealed.encode(),
            pin,
        })
    }

    /// The writes and the pin of a publish whose mailbox exists. Every put
    /// is idempotent (`OrgStore`: the same bytes again are accepted, the
    /// keyset is rewritten), so a resumed publish runs them all again. On a
    /// failure the pending publish comes back with the error.
    fn finish(
        &self,
        p: Box<Pending>,
        state_dir: &Path,
    ) -> Result<FfiOrgCreated, (Box<Pending>, OnePassError)> {
        let Pending {
            client,
            credential_seed,
            mailbox_id,
            genesis,
            roster,
            owner_account,
            sealed_keyset,
            pin,
        } = *p;
        let mut store = OrgStore::new(client, self.org_id.0);
        let done: Result<(), OnePassError> = (|| {
            store.put_lineage(0, genesis.clone())?;
            store.put_roster(1, roster.clone())?;
            store.put_owner_keyset(owner_account, sealed_keyset.clone())?;
            save_pin(state_dir, &pin)
        })();
        match done {
            Ok(()) => Ok(FfiOrgCreated {
                mailbox_id: bytes_hex(&mailbox_id),
                credential_seed: credential_seed.to_vec(),
                state: view(&pin, &HashMap::new()),
            }),
            Err(e) => Err((
                Box::new(Pending {
                    client: store.into_api(),
                    credential_seed,
                    mailbox_id,
                    genesis,
                    roster,
                    owner_account,
                    sealed_keyset,
                    pin,
                }),
                e,
            )),
        }
    }
}

#[cfg(feature = "dev-fast-kdf")]
impl OrgDraft {
    /// `publish` over a test mailbox client (`FakeMailbox`, no TLS) holding
    /// the credential of `credential_seed`.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn publish_with_client(
        &self,
        client: Box<dyn MailboxApi>,
        credential_seed: Vec<u8>,
        server_invite: String,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        name: String,
        state_dir: String,
        now: i64,
    ) -> Result<FfiOrgCreated, OnePassError> {
        let classical = Zeroizing::new(classical);
        let seed = Zeroizing::new(credential_seed);
        let connect: Connect<'_> = Box::new(move || Ok((client, seed)));
        self.publish_on(
            connect,
            &server_invite,
            &session,
            &classical,
            pq,
            name,
            Path::new(&state_dir),
            now,
        )
    }
}

/// An organisation this device follows: its mailbox (as an org store) and
/// its pin in `state_dir`. Every state it returns comes from the pin; the
/// server's answers move the pin only once fully verified.
#[derive(uniffi::Object)]
pub struct OrgClient {
    /// Also serializes every pin update of this client.
    store: Mutex<Box<dyn OrgStoreApi + Send>>,
    org_id: [u8; 16],
    state_dir: PathBuf,
}

#[uniffi::export]
impl OrgClient {
    /// The org `org_id` (32 hex) in mailbox `mailbox_id` (32 hex) on
    /// `endpoint`, with the credential of `credential_seed`. Nothing is
    /// fetched yet.
    #[uniffi::constructor]
    pub fn open(
        endpoint: FfiMailboxEndpoint,
        mailbox_id: String,
        credential_seed: Vec<u8>,
        org_id: String,
        state_dir: String,
    ) -> Result<Arc<Self>, OnePassError> {
        let seed = Zeroizing::new(credential_seed);
        let mailbox = self::mailbox_id(&mailbox_id)?;
        let org_id = org_id_of(&org_id)?;
        let mut client = MailboxClient::new(endpoint.into(), credential(&seed)?)?;
        client.open(mailbox);
        Ok(Self::build(
            Box::new(OrgStore::new(client, org_id)),
            org_id,
            PathBuf::from(state_dir),
        ))
    }

    /// The pinned state, local only (`None` before `pin`).
    pub fn state(&self) -> Result<Option<FfiOrgState>, OnePassError> {
        let _store = lock(&self.store);
        Ok(self.load()?.map(|p| view(&p, &HashMap::new())))
    }

    /// Pin the org the mailbox serves. `Mdm` and `Dns` need
    /// `expected_fingerprint` (the core checks it). `Tofu { verified: false }`
    /// from a join link compares the served fingerprint with the link's
    /// (`expected_fingerprint`): a mismatch is `OrgPinMismatch` and nothing
    /// is saved. Then the lineage and the rosters from seq 1 to the newest
    /// are verified before `pin.bin` is written. Already pinned: the same
    /// org is a `refresh`, another one `OrgPinMismatch`. `now` is not
    /// used in E1 (no time rule on a pin yet).
    pub fn pin(
        &self,
        source: FfiPinSource,
        expected_fingerprint: Option<Vec<u8>>,
        now: i64,
    ) -> Result<FfiOrgState, OnePassError> {
        let _ = now;
        let expected = expected_fingerprint.as_deref().map(fpr_array).transpose()?;
        let source = PinSource::from(source);
        let mut store = lock(&self.store);
        let lineage = store.lineage_from(0)?;
        let genesis = match lineage.first() {
            Some((0, bytes)) => bytes,
            _ => return Err(OnePassError::NotFound),
        };
        let fresh = match source {
            PinSource::Tofu { .. } => {
                let pin = pin_org(source, None, genesis)?;
                if expected.is_some_and(|f| f != pin.fingerprint()) {
                    return Err(OnePassError::OrgPinMismatch);
                }
                pin
            }
            PinSource::Mdm | PinSource::Dns => pin_org(source, expected, genesis)?,
        };
        if fresh.lineage().org_id.0 != self.org_id {
            return Err(integrity(IntegrityError::WrongContext));
        }
        match self.load()? {
            Some(old) if old.fingerprint() != fresh.fingerprint() => {
                Err(OnePassError::OrgPinMismatch)
            }
            Some(old) => {
                let lineage = store.lineage_from(old.head().generation)?;
                self.advance_and_save(&mut **store, &old, Some(&old), &lineage)
            }
            None => self.advance_and_save(&mut **store, &fresh, None, &lineage),
        }
    }

    /// Move the pin forward: the lineage from the pinned head generation,
    /// the rosters from the pinned seq to the newest. Any refusal leaves
    /// `pin.bin` byte for byte as it was. `NotFound` before `pin`.
    pub fn refresh(&self) -> Result<FfiOrgState, OnePassError> {
        let mut store = lock(&self.store);
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        let lineage = store.lineage_from(pin.head().generation)?;
        self.advance_and_save(&mut **store, &pin, Some(&pin), &lineage)
    }

    /// The user compared the fingerprint words with an admin's and they
    /// match: a TOFU pin becomes verified (`Validation` for an MDM or DNS
    /// pin, `NotFound` before `pin`).
    pub fn mark_verified(&self) -> Result<FfiOrgState, OnePassError> {
        let _store = lock(&self.store);
        let _pins = pin_lock();
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        let pin = pin.confirm_tofu(&pin.fingerprint())?;
        save_pin(&self.state_dir, &pin)?;
        Ok(view(&pin, &HashMap::new()))
    }
}

impl OrgClient {
    fn build(
        store: Box<dyn OrgStoreApi + Send>,
        org_id: [u8; 16],
        state_dir: PathBuf,
    ) -> Arc<Self> {
        Arc::new(OrgClient {
            store: Mutex::new(store),
            org_id,
            state_dir,
        })
    }

    /// The pin in the state folder; one of another org is refused.
    fn load(&self) -> Result<Option<OrgPin>, OnePassError> {
        let pin = load_pin(&self.state_dir)?;
        if pin
            .as_ref()
            .is_some_and(|p| p.lineage().org_id.0 != self.org_id)
        {
            return Err(integrity(IntegrityError::WrongContext));
        }
        Ok(pin)
    }

    /// `pin` moved forward and saved. `base`: the pin stored when the call
    /// started (`None` for a first pin).
    fn advance_and_save(
        &self,
        store: &mut dyn OrgStoreApi,
        pin: &OrgPin,
        base: Option<&OrgPin>,
        lineage: &[(u64, Vec<u8>)],
    ) -> Result<FfiOrgState, OnePassError> {
        let next = advance(store, pin, lineage)?;
        // Compare and save under the process-wide pin lock: another client
        // on the same folder may have saved meanwhile. Never write over a
        // pin other than the one this advance started from (an older pin
        // over a newer one would be a rollback): `Conflict`, the caller
        // refreshes again from what is stored.
        let _pins = pin_lock();
        let stored = self.load()?;
        if stored.as_ref() == Some(&next) {
            return Ok(view(&next, &HashMap::new()));
        }
        if stored.as_ref() != base {
            return Err(OnePassError::Conflict);
        }
        save_pin(&self.state_dir, &next)?;
        Ok(view(&next, &HashMap::new()))
    }
}

#[cfg(feature = "dev-fast-kdf")]
impl OrgClient {
    /// An org client over any org store: `OrgStore` over a `FakeMailbox`
    /// client, or `HostileOrgStore` (tests only, no TLS).
    #[doc(hidden)]
    pub fn with_store(
        store: Box<dyn OrgStoreApi + Send>,
        org_id: [u8; 16],
        state_dir: PathBuf,
    ) -> Arc<Self> {
        Self::build(store, org_id, state_dir)
    }
}

// ---- managed accounts ---------------------------------------------------------------

/// A managed account (OnePass Business): `create_account_v2` whose genesis
/// names `org_id` (32 hex). `account_id`: the id the org roster invited (the
/// join link's), or `None` for a fresh one (the org's creator, before the
/// org exists). The password crosses as UTF-8 bytes, wiped here.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn create_managed_account(
    db_path: String,
    password: Vec<u8>,
    kdf: Option<FfiKdfParams>,
    classical: Vec<u8>,
    pq: Arc<dyn FfiPqDeviceHalf>,
    name: String,
    kind: FfiDeviceKind,
    mode: FfiDeviceMode,
    org_id: String,
    account_id: Option<String>,
) -> Result<FfiCreatedAccount, OnePassError> {
    let password = Zeroizing::new(password);
    let password = std::str::from_utf8(&password).map_err(|_| invalid("password"))?;
    let classical = Zeroizing::new(classical);
    let org = ManagedGenesis {
        org_id: OrgId(org_id_of(&org_id)?),
        account_id: match account_id {
            Some(a) => parse_id(&a)?,
            None => Id::new(),
        },
    };
    let kdf = match kdf {
        Some(k) => crate::kdf_params(k)?,
        None => onepass_core::crypto::KdfParams::new_default()?,
    };
    let keys = device_keys(&classical, pq)?;
    crate::create_v2(
        &db_path,
        password,
        kdf,
        &keys,
        &name,
        kind.into(),
        mode.into(),
        Some(org),
    )
}

/// The organisation (32 hex) of the account at `db_path`, without
/// unlocking: `None` for a personal account, a pre-v2 one or an empty
/// store. Same read as the core's `Repository::genesis_org` (which needs an
/// unlocked repository): the genesis at the root of this device's trusted
/// head, walked back by parent hash through the stored lineage records
/// (each record found by its hash, so only the chain the device trusts
/// counts). No signature is checked: it reads this device's own store, as
/// `lineage_status` does. `NotFound` when a record of the chain is missing.
#[uniffi::export]
pub fn managed_account_org(db_path: String) -> Result<Option<String>, OnePassError> {
    let store = SyncStore::open(Path::new(&db_path))?;
    let Some(trust) = store.trust_state()? else {
        return Ok(None);
    };
    let records: Vec<LineageRecord> = store
        .list(RecordKind::Lineage)?
        .iter()
        .filter_map(|r| LineageRecord::decode(&r.data).ok())
        .filter(|l| l.account_id() == trust.account_id)
        .collect();
    let mut hash = trust.head.hash;
    for _ in 0..=records.len() {
        let r = records
            .iter()
            .find(|r| r.hash() == hash)
            .ok_or(OnePassError::NotFound)?;
        match r.parent() {
            None => return Ok(r.org().map(|o| bytes_hex(&o.0))),
            Some(parent) => hash = parent,
        }
    }
    Err(OnePassError::NotFound)
}
