//! Organization (OnePass Business) types of the FFI: roles, members, the
//! pinned state the apps show, the fingerprint words and the join link.
//! Swift gets display values only: never org record bytes, org secrets or
//! the owner keyset.

mod invite;
mod join;
mod pinstore;
#[cfg(feature = "dev-fast-kdf")]
mod testing;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::generator::Wordlist;
use onepass_core::lineage::LineageRecord;
use onepass_core::org::{
    JoinRequestBody, MAX_DISPLAY_NAME_BYTES, MemberRef, MemberState, ORG_FORMAT, OrgChangeBody,
    OrgChangeKind, OrgGenesisBody, OrgHeadInfo, OrgId, OrgKeyset, OrgMember, OrgPin, OrgSecrets,
    PinSource, Role, RoleSet, RosterBody, RosterCheckpoint, SealedOrgKeyset, VerifiedJoin,
    activate_member, check_transition, dns_txt_value, fingerprint_words, founding_roster,
    invite_member, join_code_of, open_org_keyset, parse_dns_txt, pin_org, rebase_roster,
    seal_org_keyset, sign_join_request, sign_org_change, sign_org_genesis, sign_roster,
    verify_org_genesis,
};
use onepass_core::repo::ManagedGenesis;
use onepass_core::store::{RecordKind, RecordStore};
use onepass_core::sync::SyncStore;
use onepass_core::{Id, IntegrityError};
use onepass_mailbox::org::ORG_JOIN_KIND;
use onepass_mailbox::{
    CredentialKey, ErrorCode, MailboxApi, MailboxClient, MailboxError, OrgStore, OrgStoreApi,
    OrgStoreError,
};
use onepass_mailbox_proto::{CredentialRole, put_kinds_of};
use zeroize::Zeroizing;

use crate::convert::{bytes_hex, hex_bytes, id_hex, parse_id};
use crate::devices::{FfiDeviceKind, FfiDeviceMode};
use crate::error::{OnePassError, invalid};
use crate::mailbox::{FfiMailboxEndpoint, LABEL, credential, fresh_credential, mailbox_id};
use crate::rotation::{FfiPqDeviceHalf, device_keys};
use crate::session::Session;
use crate::types::{FfiCreatedAccount, FfiKdfParams};
use join::{JoinCache, Verdict};
use pinstore::{
    Bound, LocalAccess, LocalInvite, add_invite, load_access, load_invites, load_pin, pin_lock,
    save_access, save_pin,
};

pub use invite::{org_invite_encode, org_invite_parse};
#[cfg(feature = "dev-fast-kdf")]
pub use testing::TestOrgServer;
/// The largest join request an org client keeps (tests only).
#[cfg(feature = "dev-fast-kdf")]
#[doc(hidden)]
pub const ORG_JOIN_REQUEST_MAX: usize = join::JOIN_REQUEST_MAX;

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

/// The content of a join link (see `invite`). `Debug` leaves out the
/// credential seed and the member token.
#[derive(uniffi::Record, Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for FfiOrgInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiOrgInvite")
            .field("server_url", &self.server_url)
            .field("mailbox_id", &self.mailbox_id)
            .field("org_id", &self.org_id)
            .field("account_id", &self.account_id)
            .field("fingerprint", &bytes_hex(&self.fingerprint))
            .field("nonce", &bytes_hex(&self.nonce))
            .field("credential_seed", &"<redacted>")
            .field("member_token", &"<redacted>")
            .field("domain", &self.domain)
            .finish()
    }
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

fn role_set(roles: &[FfiOrgRole]) -> RoleSet {
    ROLES
        .iter()
        .filter(|(_, f)| roles.contains(f))
        .fold(RoleSet::EMPTY, |s, (r, _)| s.with(*r))
}

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

/// What `OrgDraft::publish` returns. No secret: the org mailbox's managing
/// credential is the one of the seed the app passed (R39).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgCreated {
    /// 32 hex.
    pub mailbox_id: String,
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

/// A mailbox client holding the org mailbox's managing credential.
type Connect<'a> = Box<dyn FnOnce() -> Result<Box<dyn MailboxApi>, OnePassError> + 'a>;

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
    /// `server_invite` with the credential of `credential_seed` (R39: the
    /// app generates it with `mailbox_generate_credential` and keeps it in
    /// its keychain BEFORE calling, so the creator never holds a manager
    /// credential only in memory; it becomes the creator's own org mailbox
    /// credential), then writes the genesis
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
        credential_seed: Vec<u8>,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        name: String,
        state_dir: String,
        now: i64,
    ) -> Result<FfiOrgCreated, OnePassError> {
        let classical = Zeroizing::new(classical);
        let seed = Zeroizing::new(credential_seed);
        let connect: Connect<'_> = Box::new(move || {
            let client: Box<dyn MailboxApi> =
                Box::new(MailboxClient::new(endpoint.into(), credential(&seed)?)?);
            Ok(client)
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
                        let mut client = connect()?;
                        let created = client.create(Some(server_invite.as_bytes()), LABEL)?;
                        Ok((signed, client, created.mailbox_id))
                    });
                match created {
                    // Nothing exists anywhere yet: the draft stays fresh.
                    Err(e) => {
                        *stage = Stage::Fresh(keyset.secrets);
                        return Err(e);
                    }
                    Ok((signed, client, mailbox_id)) => Box::new(Pending {
                        client,
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
                state: view(&pin, &HashMap::new()),
            }),
            Err(e) => Err((
                Box::new(Pending {
                    client: store.into_api(),
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
    /// the org mailbox's managing credential.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn publish_with_client(
        &self,
        client: Box<dyn MailboxApi>,
        server_invite: String,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        name: String,
        state_dir: String,
        now: i64,
    ) -> Result<FfiOrgCreated, OnePassError> {
        let classical = Zeroizing::new(classical);
        let connect: Connect<'_> = Box::new(move || Ok(client));
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

/// What `create_invite` returns: the join link to hand over (it carries the
/// invite credential seed and the member token: share it, never store it)
/// and the invited account id (32 hex). `Debug` leaves out the link.
#[derive(uniffi::Record, Clone, PartialEq, Eq)]
pub struct FfiInviteLink {
    pub link: String,
    pub account_id: String,
}

impl std::fmt::Debug for FfiInviteLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiInviteLink")
            .field("link", &"<redacted>")
            .field("account_id", &self.account_id)
            .finish()
    }
}

/// What `post_join_request` returns: the join code (5 words) the member
/// reads to the admin.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiJoinPosted {
    pub code_words: Vec<String>,
}

/// A verified join request waiting for the admin.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiJoinRequest {
    /// 32 hex.
    pub account_id: String,
    pub display_name: String,
    pub devices: Vec<FfiOrgDevice>,
    /// The join code (5 words) the member reads out.
    pub code_words: Vec<String>,
    /// This device issued the invitation (`invites.bin`).
    pub issued_here: bool,
    pub invite_label: Option<String>,
    /// Always false from `join_requests` (Invited members only).
    pub in_roster: bool,
}

/// `Write` on join requests only, for the invite credential (A2).
const INVITE_CREDENTIAL_LABEL: &[u8] = b"org-invite";
/// Life of the one-use `managed` mailbox token of an invitation (R4).
const MEMBER_TOKEN_TTL_HOURS: u16 = 168;

fn validation(field: &str, reason: &str) -> OnePassError {
    OnePassError::Validation {
        field: field.into(),
        reason: reason.into(),
    }
}

/// R12: 1 to 64 bytes of UTF-8 and the core's character rules.
fn check_display_name(body: &JoinRequestBody) -> Result<(), OnePassError> {
    let name = &body.display_name;
    if name.is_empty()
        || name.len() > MAX_DISPLAY_NAME_BYTES
        || matches!(
            body.check(),
            Err(onepass_core::Error::InvalidFormat(
                "join request display name"
            ))
        )
    {
        return Err(validation(
            "display_name",
            "1 to 64 bytes, no control or invisible character",
        ));
    }
    Ok(())
}

/// This device as a signer: its account, its public half as the session's
/// store trusts it, with the keys checked to match.
struct Signer {
    account: Id,
    me: DevicePublic,
    keys: DeviceKeys,
}

impl Signer {
    fn of(
        session: &Session,
        classical: &[u8],
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<Signer, OnePassError> {
        let keys = device_keys(classical, pq)?;
        let (account, me) = session.with(|repo| {
            let me = repo
                .store()
                .trust_state()?
                .ok_or_else(|| invalid("device keys"))?
                .me;
            Ok((repo.account().params.account_id, me))
        })?;
        Signer::with_keys(account, keys, me)
    }

    fn with_keys(account: Id, keys: DeviceKeys, me: DevicePublic) -> Result<Signer, OnePassError> {
        if keys.public(me.device_id)? != me {
            return Err(invalid("device keys"));
        }
        Ok(Signer { account, me, keys })
    }
}

/// An organisation this device follows: its mailbox (as an org store) and
/// its pin in `state_dir`. Every state it returns comes from the pin; the
/// server's answers move the pin only once fully verified.
#[derive(uniffi::Object)]
pub struct OrgClient {
    /// Also serializes every pin update of this client. Locked before
    /// `joins` whenever both are held.
    store: Mutex<Box<dyn OrgStoreApi + Send>>,
    org_id: [u8; 16],
    state_dir: PathBuf,
    /// The mailbox server's URL, named in the join links this client makes.
    server_url: String,
    /// The join requests read so far (R2).
    joins: Mutex<JoinCache>,
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
        let server_url = endpoint.base_url.clone();
        let mut client = MailboxClient::new(endpoint.into(), credential(&seed)?)?;
        client.open(mailbox);
        Ok(Self::build(
            Box::new(OrgStore::new(client, org_id)),
            org_id,
            PathBuf::from(state_dir),
            server_url,
        ))
    }

    /// The pinned state, local only (`None` before `pin`).
    pub fn state(&self) -> Result<Option<FfiOrgState>, OnePassError> {
        let _store = lock(&self.store);
        Ok(self.load()?.map(|p| self.show(&p)))
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
                let pin = self.refreshed(&mut **store, &old)?;
                Ok(self.show(&pin))
            }
            None => {
                let pin = self.advance_and_save(&mut **store, &fresh, None, &lineage)?;
                Ok(self.show(&pin))
            }
        }
    }

    /// Move the pin forward: the lineage from the pinned head generation,
    /// the rosters from the pinned seq to the newest. Any refusal leaves
    /// `pin.bin` byte for byte as it was. Then the join feed is read for
    /// what changed (R28), so member names follow; a failure there keeps
    /// the names as they were and does not fail the refresh. `NotFound`
    /// before `pin`.
    pub fn refresh(&self) -> Result<FfiOrgState, OnePassError> {
        let mut store = lock(&self.store);
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        let pin = self.refreshed(&mut **store, &pin)?;
        let _ = self.poll_joins(&mut **store);
        Ok(self.show(&pin))
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
        Ok(self.show(&pin))
    }

    /// Invites a member (R4) with a signed roster edit by this device: a
    /// new Invited member (a fresh account id, `roles`, the commitment of a
    /// random 32-byte nonce) at roster seq + 1, checked against the core
    /// rules first (`Integrity { org_role_denied }`, nothing written). Then
    /// a fresh credential is granted `Write` on join requests only (kind
    /// 32) and a one-use `managed` mailbox token is minted (168 hours). The
    /// link names this client's server, the org mailbox, the pinned
    /// fingerprint, the account id, the nonce, the credential seed, the
    /// token and `domain`; Rust writes neither the seed nor the token.
    /// `invites.bin` keeps the account id, nonce, the invite credential's
    /// id, `label` and `now`; it is read before any server write (R28), and
    /// failing to save it once the server writes are done does not fail the
    /// call (the link is returned, the label is lost). A token mint failure
    /// revokes the just-granted credential, best effort. Any failure after
    /// the roster write leaves the Invited member in the roster (withdrawn
    /// by removing it). `NotFound` before `pin`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_invite(
        &self,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        label: String,
        domain: Option<String>,
        roles: Vec<FfiOrgRole>,
        now: i64,
    ) -> Result<FfiInviteLink, OnePassError> {
        let classical = Zeroizing::new(classical);
        let mut store = lock(&self.store);
        let mailbox = store
            .mailbox()
            .mailbox()
            .ok_or_else(|| invalid("mailbox"))?;
        let mut invite = FfiOrgInvite {
            server_url: self.server_url.clone(),
            mailbox_id: bytes_hex(&mailbox),
            org_id: bytes_hex(&self.org_id),
            account_id: bytes_hex(&[0; 16]),
            fingerprint: vec![0; 32],
            nonce: vec![0; 32],
            credential_seed: vec![0; 32],
            member_token: vec![0; 32],
            domain,
        };
        // The server URL and the domain are checked before anything is written.
        org_invite_encode(invite.clone())?;
        // A broken invites.bin fails here, before any server write.
        load_invites(&self.state_dir)?;
        let signer = Signer::of(&session, &classical, pq)?;
        let roles = role_set(&roles);
        let (pin, invitation) = self.signed_edit(&mut **store, &signer, |prev| {
            Ok(invite_member(prev, [0; 32], roles)?)
        })?;
        let credential = fresh_credential()?;
        let credential_id = store.mailbox().grant(
            credential.public_key().to_bytes(),
            CredentialRole::Write,
            Some(put_kinds_of(&[ORG_JOIN_KIND])),
            INVITE_CREDENTIAL_LABEL,
        )?;
        let token = match store.create_member_invite(MEMBER_TOKEN_TTL_HOURS) {
            Ok(t) => Zeroizing::new(t),
            Err(e) => {
                // No link carries it: best effort, the mint error is the answer.
                let _ = store.mailbox().revoke(credential_id);
                return Err(e.into());
            }
        };
        let account_id = id_hex(invitation.account_id);
        invite.account_id = account_id.clone();
        invite.fingerprint = pin.fingerprint().to_vec();
        invite.nonce = invitation.nonce.to_vec();
        invite.credential_seed = credential.seed().to_vec();
        invite.member_token = token.to_vec();
        let link = org_invite_encode(invite)?;
        // The server holds the invitation now: a local write failure loses
        // only `issued_here` and the label, never the link (R28).
        let _ = add_invite(
            &self.state_dir,
            LocalInvite {
                account_id: invitation.account_id.0,
                nonce: invitation.nonce,
                credential_id,
                label,
                created_at: now,
            },
        );
        Ok(FfiInviteLink { link, account_id })
    }

    /// Posts the join request of `session`'s managed account for `invite`
    /// through this client (the invite credential), signed by this device.
    /// The session must be the invited account (`Validation { field:
    /// "account" }`) of a managed genesis naming this org (`Validation {
    /// field: "org" }`) made on this device (R20, `Validation { field:
    /// "device" }`). The request names the pinned fingerprint and the
    /// member's own org mailbox credential, the one of `credential_seed`
    /// (R27, R35): the app generates it (`mailbox_generate_credential`) and
    /// keeps it in its keychain BEFORE posting, so a crash after the post
    /// never loses the key admins grant; a repost passes the same seed. The
    /// link's credential only reads, pins and posts, and never becomes the
    /// member's. Once Active the member reopens with its own seed and calls
    /// `revoke_own_credential` on the link's client.
    /// `display_name`: 1 to 64 bytes of UTF-8, no control or invisible
    /// character (`Validation { field: "display_name" }`). Posting again
    /// replaces the request. Returns the join code, the 5 words the member
    /// reads to the admin.
    /// `NotFound` before `pin`.
    #[allow(clippy::too_many_arguments)]
    pub fn post_join_request(
        &self,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        invite: FfiOrgInvite,
        display_name: String,
        credential_seed: Vec<u8>,
        now: i64,
    ) -> Result<FfiJoinPosted, OnePassError> {
        let classical = Zeroizing::new(classical);
        let own = credential(&Zeroizing::new(credential_seed))?;
        if org_id_of(&invite.org_id)? != self.org_id {
            return Err(validation(
                "org",
                "the invitation is for another organisation",
            ));
        }
        let account = parse_id(&invite.account_id)?;
        let nonce: [u8; 32] = invite
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| invalid("nonce"))?;
        let mut store = lock(&self.store);
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        let (genesis, me, kem) = session.with(|repo| {
            let params = &repo.account().params;
            if params.account_id != account {
                return Err(validation("account", "not the invited account"));
            }
            let me = repo
                .store()
                .trust_state()?
                .ok_or_else(|| invalid("device keys"))?
                .me;
            let genesis = repo
                .store()
                .list(RecordKind::Lineage)?
                .into_iter()
                .find(|r| {
                    matches!(LineageRecord::decode(&r.data),
                        Ok(LineageRecord::Genesis(g)) if g.body.account_id == account)
                })
                .ok_or(OnePassError::NotFound)?
                .data;
            Ok((genesis, me, params.kem_pub.clone()))
        })?;
        let Ok(LineageRecord::Genesis(g)) = LineageRecord::decode(&genesis) else {
            return Err(OnePassError::NotFound);
        };
        if g.body.org != Some(self.org_id) {
            return Err(validation(
                "org",
                "not a managed account of this organisation",
            ));
        }
        if g.body.creator.device_id != me.device_id {
            return Err(validation(
                "device",
                "join from the device that made the account",
            ));
        }
        let signer = Signer::with_keys(account, device_keys(&classical, pq)?, me)?;
        let body = JoinRequestBody {
            format: ORG_FORMAT,
            org_id: OrgId(self.org_id),
            account_id: account,
            invite_nonce: nonce,
            pinned_fpr: pin.fingerprint(),
            account_genesis: genesis,
            devices: vec![signer.me],
            display_name,
            mailbox_credential: own.public_key().to_bytes(),
            account_kem_pub: kem,
            issued_at: now,
        };
        check_display_name(&body)?;
        let signed = sign_join_request(body, &signer.keys)?;
        let code = join_code_of(&signed, Wordlist::EffEnglish)?;
        store.put_join_request(account.0, signed.encode())?;
        Ok(FfiJoinPosted {
            code_words: code.into_iter().collect(),
        })
    }

    /// A one-use `managed` mailbox token (32 bytes, 168 hours) for the
    /// creator's own account mailbox on this server (R32): the creator has
    /// no join link, so its device mints one with the org mailbox's manager
    /// credential right after `publish` and spends it at once with
    /// `mailbox_create_managed`. Rust keeps no copy. `Forbidden` for a
    /// credential that does not manage the org mailbox.
    pub fn mint_member_token(&self) -> Result<Vec<u8>, OnePassError> {
        let mut store = lock(&self.store);
        Ok(store.create_member_invite(MEMBER_TOKEN_TTL_HOURS)?)
    }

    /// Revokes the credential this client holds, on the server (a
    /// credential may revoke itself): the member's device drops the link's
    /// credential once it uses its own (R27). The client fails from then on.
    pub fn revoke_own_credential(&self) -> Result<(), OnePassError> {
        let store = lock(&self.store);
        let mailbox = store.mailbox();
        mailbox.revoke(mailbox.credential_key().id())?;
        Ok(())
    }

    /// The verified join requests of Invited members, oldest first (issue
    /// time, then account id). Reads only what changed since the last call
    /// (R2: the first call, and a feed the server restarts, read it whole).
    /// A request that does not verify against the pinned roster and
    /// fingerprint, or whose credential is no Ed25519 key (R17), is dropped
    /// and counted nowhere. Requests of members past Invited only name them
    /// (R25) and are not listed, so `in_roster` is false here.
    /// `issued_here` and `invite_label` come from this device's
    /// `invites.bin`. `NotFound` before `pin`.
    pub fn join_requests(&self) -> Result<Vec<FfiJoinRequest>, OnePassError> {
        let mut store = lock(&self.store);
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        let invites = load_invites(&self.state_dir)?;
        self.poll_joins(&mut **store)?;
        let mut joins = lock(&self.joins);
        let mut out: Vec<(i64, FfiJoinRequest)> = joins
            .verdicts(&pin)
            .into_iter()
            .filter_map(|v| match v {
                Verdict::Invited {
                    joined,
                    code_words,
                    issued_at,
                } => {
                    let account = joined.account_id();
                    let local = invites.iter().find(|i| i.account_id == account.0);
                    Some((
                        issued_at,
                        FfiJoinRequest {
                            account_id: id_hex(account),
                            display_name: joined.display_name().to_owned(),
                            devices: joined
                                .devices()
                                .iter()
                                .map(|d| FfiOrgDevice {
                                    fingerprint: bytes_hex(&d.fingerprint()),
                                    name: None,
                                })
                                .collect(),
                            code_words,
                            issued_here: local.is_some(),
                            invite_label: local.map(|i| i.label.clone()),
                            in_roster: false,
                        },
                    ))
                }
                Verdict::Member(_) | Verdict::Dropped => None,
            })
            .collect();
        out.sort_by(|a, b| (a.0, &a.1.account_id).cmp(&(b.0, &b.1.account_id)));
        Ok(out.into_iter().map(|(_, r)| r).collect())
    }

    /// Deletes the join request of `account_id` (32 hex) and, when this
    /// device issued the invitation, revokes its link credential (best
    /// effort, R27). The roster is untouched: the invitation stands (and its
    /// member token stays valid until it expires) until its Invited member
    /// is removed, a signed edit the app offers apart.
    pub fn decline_join_request(&self, account_id: String) -> Result<(), OnePassError> {
        let account = parse_id(&account_id)?;
        let mut store = lock(&self.store);
        store.delete_join_request(account.0)?;
        lock(&self.joins).remove(&account.0);
        if let Ok(invites) = load_invites(&self.state_dir) {
            for i in invites.iter().filter(|i| i.account_id == account.0) {
                let _ = store.mailbox().revoke(i.credential_id);
            }
        }
        Ok(())
    }
}

impl OrgClient {
    fn build(
        store: Box<dyn OrgStoreApi + Send>,
        org_id: [u8; 16],
        state_dir: PathBuf,
        server_url: String,
    ) -> Arc<Self> {
        Arc::new(OrgClient {
            store: Mutex::new(store),
            org_id,
            state_dir,
            server_url,
            joins: Mutex::new(JoinCache::new()),
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
    ) -> Result<OrgPin, OnePassError> {
        let next = advance(store, pin, lineage)?;
        // Compare and save under the process-wide pin lock: another client
        // on the same folder may have saved meanwhile. Never write over a
        // pin other than the one this advance started from (an older pin
        // over a newer one would be a rollback): `Conflict`, the caller
        // refreshes again from what is stored.
        let _pins = pin_lock();
        let stored = self.load()?;
        if stored.as_ref() == Some(&next) {
            return Ok(next);
        }
        if stored.as_ref() != base {
            return Err(OnePassError::Conflict);
        }
        save_pin(&self.state_dir, &next)?;
        Ok(next)
    }

    /// Reads what changed in the join feed since the last read into the
    /// cache (R2).
    fn poll_joins(&self, store: &mut dyn OrgStoreApi) -> Result<(), OnePassError> {
        let mut joins = lock(&self.joins);
        let delta = store.join_requests_since(&mut joins.feed)?;
        joins.apply(&self.org_id, delta);
        Ok(())
    }

    /// The pin as the apps show it, member names from the verified join
    /// requests read so far (R25; no network).
    fn show(&self, pin: &OrgPin) -> FfiOrgState {
        view(pin, &lock(&self.joins).names(pin))
    }

    /// The pin refreshed from the server (the lineage from its head
    /// generation, the rosters from its seq).
    fn refreshed(&self, store: &mut dyn OrgStoreApi, pin: &OrgPin) -> Result<OrgPin, OnePassError> {
        let lineage = store.lineage_from(pin.head().generation)?;
        self.advance_and_save(store, pin, Some(pin), &lineage)
    }

    /// One signed roster edit, the path of every roster change: `edit`
    /// builds the candidate from the pinned roster; the core rules check it
    /// for this device (`Integrity { org_role_denied }`, nothing written);
    /// it is signed and put at seq + 1. A seq taken meanwhile (`Taken`, or
    /// `Contended`): refresh, then once more: the candidate rebased over the
    /// roster that won the seq (core `rebase_roster`), or, when the new pin
    /// is not that one sibling (nothing landed, or several rosters did),
    /// `edit` again on the new pin. A second loss is `Conflict`. The pin then
    /// moves through the verified path, and `edit`'s output comes back with
    /// it.
    fn signed_edit<T>(
        &self,
        store: &mut dyn OrgStoreApi,
        signer: &Signer,
        edit: impl FnMut(&RosterBody) -> Result<(RosterBody, T), OnePassError>,
    ) -> Result<(OrgPin, T), OnePassError> {
        self.signed_edit_over(store, signer, edit)
            .map(|(pin, out, _)| (pin, out))
    }

    /// `signed_edit`, with the roster the edit was finally put over (after
    /// a rebase, the one that won the seq, not the pin read first).
    fn signed_edit_over<T>(
        &self,
        store: &mut dyn OrgStoreApi,
        signer: &Signer,
        mut edit: impl FnMut(&RosterBody) -> Result<(RosterBody, T), OnePassError>,
    ) -> Result<(OrgPin, T, RosterBody), OnePassError> {
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        let base = pin.roster().ok_or(OnePassError::NotFound)?.clone();
        let (mine, out) = edit(&base)?;
        match put_edit(store, signer, &pin, &base, mine.clone())? {
            Ok(()) => return Ok((self.refreshed(store, &pin)?, out, base)),
            Err(OrgStoreError::Taken | OrgStoreError::Contended) => {}
            Err(e) => return Err(e.into()),
        }
        let fresh = self.refreshed(store, &pin)?;
        let theirs = fresh.roster().ok_or(OnePassError::NotFound)?;
        let (next, out) = if theirs.seq == mine.seq {
            let rebased = rebase_roster(fresh.lineage(), &base, &mine, theirs, &signer.me)?;
            (rebased, out)
        } else {
            edit(theirs)?
        };
        put_edit(store, signer, &fresh, theirs, next)??;
        let over = theirs.clone();
        Ok((self.refreshed(store, &fresh)?, out, over))
    }
}

/// `next` checked by the core rules for `signer` against `prev` (the roster
/// of `pin`), signed and put at its seq. The outer error is a refusal
/// before any write; the inner one the store's answer.
fn put_edit(
    store: &mut dyn OrgStoreApi,
    signer: &Signer,
    pin: &OrgPin,
    prev: &RosterBody,
    next: RosterBody,
) -> Result<Result<(), OrgStoreError>, OnePassError> {
    check_transition(pin.lineage(), prev, &next, &signer.me)?;
    let seq = next.seq;
    let signed = sign_roster(next, &signer.me, &signer.keys)?;
    Ok(store.put_roster(seq, signed.encode()))
}

// ---- roster edits, owners and the owner keyset -------------------------------------

/// A signed roster change on one member (account id: 32 hex).
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum FfiRosterEdit {
    /// An Invited member whose verified join request this client has read
    /// becomes Active with `roles` (in place of the invitation's).
    Accept {
        account_id: String,
        roles: Vec<FfiOrgRole>,
    },
    SetRoles {
        account_id: String,
        roles: Vec<FfiOrgRole>,
    },
    Suspend {
        account_id: String,
    },
    Reactivate {
        account_id: String,
    },
    /// Removed for good (kept in the roster). An Invited member: the
    /// invitation is withdrawn.
    Remove {
        account_id: String,
    },
}

impl FfiRosterEdit {
    fn account_id(&self) -> &str {
        match self {
            FfiRosterEdit::Accept { account_id, .. }
            | FfiRosterEdit::SetRoles { account_id, .. }
            | FfiRosterEdit::Suspend { account_id }
            | FfiRosterEdit::Reactivate { account_id }
            | FfiRosterEdit::Remove { account_id } => account_id,
        }
    }
}

/// What an edit does to its member, read from the pinned roster before
/// anything is signed.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiEditSummary {
    /// The display name from the member's verified join request, else its
    /// account id (32 hex).
    pub member_name: String,
    /// The member's devices once the edit is made.
    pub device_count: u32,
    pub roles_before: Vec<FfiOrgRole>,
    pub roles_after: Vec<FfiOrgRole>,
    /// `None` for a member not in the pinned roster (never for these edits).
    pub state_before: Option<FfiMemberState>,
    pub state_after: FfiMemberState,
    /// The core rules let this device sign it.
    pub allowed: bool,
}

/// What `edit_roster` returns: the pinned state after the edit, and
/// whether the member's org mailbox access now follows the roster (R29).
/// False: the roster edit stands, the server access does not follow yet;
/// the app says so and offers `update_member_access` (R38 (e)).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiEditOutcome {
    pub state: FfiOrgState,
    pub server_access_updated: bool,
}

/// Grant label of a member's own org mailbox credential.
const MEMBER_CREDENTIAL_LABEL: &[u8] = b"org-member";

/// Roles an edit may set: `Owner` and `RecoveryOfficer` change only
/// through the org lineage.
fn edit_roles(roles: &[FfiOrgRole]) -> Result<RoleSet, OnePassError> {
    if roles.contains(&FfiOrgRole::Owner) {
        return Err(validation("roles", "owner via lineage"));
    }
    if roles.contains(&FfiOrgRole::RecoveryOfficer) {
        return Err(validation("roles", "recovery officer via lineage"));
    }
    Ok(role_set(roles))
}

/// The candidate roster of `edit` after `prev`, the one path of both the
/// summary and the write (so they never disagree). `by`: the editing
/// account (a removal names it). `joined`: the member's verified join
/// request (`Accept` needs it, `NotFound` otherwise). A Removed member
/// takes no edit (`Integrity { org_role_denied }`); the permission rules
/// are otherwise `check_transition`'s.
fn next_roster(
    prev: &RosterBody,
    edit: &FfiRosterEdit,
    by: Id,
    joined: Option<&VerifiedJoin>,
    now: i64,
) -> Result<RosterBody, OnePassError> {
    let account = parse_id(edit.account_id())?;
    let p = prev.member(account).ok_or(OnePassError::NotFound)?;
    if matches!(p.state, MemberState::Removed { .. }) {
        // Removed is for good: no candidate to show or sign.
        return Err(integrity(IntegrityError::OrgRoleDenied));
    }
    let change = |f: &dyn Fn(&mut OrgMember)| -> Result<RosterBody, OnePassError> {
        let mut next = prev.next()?;
        if let Some(m) = next.members.iter_mut().find(|m| m.account_id == account) {
            f(m);
        }
        Ok(next)
    };
    let next = match edit {
        FfiRosterEdit::Accept { roles, .. } => {
            let roles = edit_roles(roles)?;
            let joined = joined
                .filter(|j| j.account_id() == account)
                .ok_or(OnePassError::NotFound)?;
            let mut next = activate_member(prev, joined)?;
            if let Some(m) = next.members.iter_mut().find(|m| m.account_id == account) {
                m.roles = roles;
            }
            next
        }
        FfiRosterEdit::SetRoles { roles, .. } => {
            let roles = edit_roles(roles)?;
            if p.roles.contains(Role::Owner) {
                return Err(validation("roles", "owner via lineage"));
            }
            change(&|m| m.roles = roles)?
        }
        FfiRosterEdit::Suspend { .. } => change(&|m| m.state = MemberState::Suspended)?,
        FfiRosterEdit::Reactivate { .. } => change(&|m| m.state = MemberState::Active)?,
        FfiRosterEdit::Remove { .. } => change(&|m| {
            m.state = MemberState::Removed { at: now, by };
            m.roles = RoleSet::EMPTY;
            m.devices.clear();
        })?,
    };
    next.check()?;
    Ok(next)
}

/// The org mailbox access a roster entry gives (R29): `None` to revoke.
fn access_of(m: &OrgMember) -> Option<(CredentialRole, Option<[u8; 32]>)> {
    let manager = [Role::Owner, Role::Admin, Role::UserManager];
    match m.state {
        MemberState::Removed { .. } => None,
        MemberState::Suspended => Some((CredentialRole::Read, None)),
        MemberState::Active | MemberState::Invited
            if manager.iter().any(|r| m.roles.contains(*r)) =>
        {
            Some((CredentialRole::Manage, None))
        }
        MemberState::Active | MemberState::Invited => {
            Some((CredentialRole::Write, Some(put_kinds_of(&[ORG_JOIN_KIND]))))
        }
    }
}

/// What `follow_access` did.
#[derive(Clone, Copy, Default)]
struct Access {
    /// The server holds the access the roster entry gives.
    updated: bool,
    /// This call granted the member's credential: the link credential can
    /// go (R38 (d)).
    granted: bool,
}

/// The server refused a grant because it already knows that key (in this
/// mailbox or another, even revoked).
fn known_key(e: &MailboxError) -> bool {
    matches!(e, MailboxError::Server(ErrorCode::Malformed))
}

/// Moves the member's own org mailbox credential to what its roster entry
/// `m` gives (R29), from what this device knows of it (R38):
///
/// - accepting it here (`was_invited` and `m` Active): the key of the
///   verified request `joined` is granted and bound in `access.bin`
///   (`Granted`; `Refused` when the server or another bound member already
///   holds that key, never moved from here; `Pending` on any other
///   failure, granted by the next update);
/// - bound here before: that key, whatever the stored request says now
///   (`Granted`: `set_role`, else a grant when the server no longer knows
///   it, or a revoke; `Pending`: a grant, never a role change, and a
///   removal revokes it, done only when the revoke applied; `Refused`:
///   nothing);
/// - accepted elsewhere: the key of the verified request `joined` (the
///   server's first-writer rule and the shared-key check stand behind it),
///   as `Granted`, unless this device bound that key to another member.
///
/// A revoke the server answers `NotFound` is done only for a `Granted`
/// key (R42); a binding `access.bin` could not keep is reported as not
/// updated. An Invited member, or one removed while Invited, never had
/// any.
fn follow_access(
    mailbox: &dyn MailboxApi,
    state_dir: &Path,
    m: &OrgMember,
    joined: Option<&VerifiedJoin>,
    was_invited: bool,
) -> Access {
    let done = Access {
        updated: true,
        granted: false,
    };
    if m.state == MemberState::Invited || (was_invited && m.state != MemberState::Active) {
        return done;
    }
    let account = m.account_id.0;
    let Ok(bound) = load_access(state_dir) else {
        return Access::default();
    };
    let target = access_of(m);
    // False when the binding could not be kept: the caller reports the
    // access as not updated, so the loss is never silent.
    let save = |key: [u8; 32], bound: Bound| -> bool {
        save_access(
            state_dir,
            LocalAccess {
                account_id: account,
                key,
                bound,
            },
        )
        .is_ok()
    };
    let grant = |key: [u8; 32], role: CredentialRole, kinds: Option<[u8; 32]>| -> Bound {
        match mailbox.grant(key, role, kinds, MEMBER_CREDENTIAL_LABEL) {
            Ok(_) => Bound::Granted,
            Err(e) if known_key(&e) => Bound::Refused,
            Err(_) => Bound::Pending,
        }
    };
    let granted = |b: Bound, saved: bool| Access {
        updated: b == Bound::Granted && saved,
        granted: b == Bound::Granted,
    };
    if was_invited {
        let (Some(key), Some((role, kinds))) = (joined.map(|j| *j.mailbox_credential()), target)
        else {
            return Access::default();
        };
        let taken = bound
            .iter()
            .any(|a| a.account_id != account && a.key == key);
        let b = if taken {
            Bound::Refused
        } else {
            grant(key, role, kinds)
        };
        let saved = save(key, b);
        return granted(b, saved);
    }
    let (key, state) = match bound.iter().find(|a| a.account_id == account) {
        Some(a) => (a.key, Some(a.bound)),
        // A key this device bound to another member is never this one's.
        None => match joined.map(|j| *j.mailbox_credential()) {
            Some(key) if !bound.iter().any(|a| a.key == key) => (key, None),
            _ => return Access::default(),
        },
    };
    let id = CredentialKey::from_bytes(key).id();
    match (state, target) {
        (Some(Bound::Refused), _) => Access::default(),
        (Some(Bound::Pending), Some((role, kinds))) => {
            let b = grant(key, role, kinds);
            let saved = b == Bound::Pending || save(key, b);
            granted(b, saved)
        }
        // Removed: the key is revoked. A server that no longer knows it is
        // done only for a key this device saw granted (R42); a Pending one
        // (answer lost) or one read from the stored request may name a key
        // the member never used, so that stays not updated and the app
        // warns.
        (_, None) => Access {
            updated: match mailbox.revoke(id) {
                Ok(()) => true,
                Err(MailboxError::Server(ErrorCode::NotFound)) => state == Some(Bound::Granted),
                Err(_) => false,
            },
            granted: false,
        },
        (_, Some((role, kinds))) => match mailbox.set_role(id, role, kinds) {
            Ok(()) => done,
            Err(MailboxError::Server(ErrorCode::NotFound)) => {
                let b = grant(key, role, kinds);
                let saved = state.is_none() || b == Bound::Pending || save(key, b);
                granted(b, saved)
            }
            Err(_) => Access::default(),
        },
    }
}

impl OrgClient {
    /// Revokes the link credentials of the invitations this device issued
    /// to `account` (best effort).
    fn revoke_links(&self, mailbox: &dyn MailboxApi, account: Id) {
        if let Ok(invites) = load_invites(&self.state_dir) {
            for i in invites.iter().filter(|i| i.account_id == account.0) {
                let _ = mailbox.revoke(i.credential_id);
            }
        }
    }
}

/// Unix seconds now (the `at` a removal summary shows).
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `roster` after a lineage change: `head`'s org head, the `Owner` bit on
/// exactly its owners (X9, X10); the owners' keys and devices are already
/// the roster's (a promoted member is Active, its `MemberRef` built from
/// its entry).
fn mirror_owners(prev: &RosterBody, head: &OrgHeadInfo) -> Result<RosterBody, OnePassError> {
    let mut next = prev.next()?;
    next.org_head = head.hash;
    for m in next.members.iter_mut() {
        m.roles = if head.owners.iter().any(|o| o.account_id == m.account_id) {
            m.roles.with(Role::Owner)
        } else {
            m.roles.without(Role::Owner)
        };
    }
    Ok(next)
}

#[uniffi::export]
impl OrgClient {
    /// What `edit` would do, from the pinned roster and the join requests
    /// already read only: no network, no signature (the keys only give
    /// this device's public half). `allowed` is the core rules' answer for
    /// this device on the same candidate `edit_roster` signs. Refusals
    /// before the rules (`Validation { roles }`, `NotFound` for an unknown
    /// member or an `Accept` without a verified request, `Integrity {
    /// org_role_denied }` for a Removed member) are errors here too. A
    /// removal shows the current time as its `at`.
    pub fn summarize(
        &self,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        edit: FfiRosterEdit,
    ) -> Result<FfiEditSummary, OnePassError> {
        let classical = Zeroizing::new(classical);
        let signer = Signer::of(&session, &classical, pq)?;
        let account = parse_id(edit.account_id())?;
        let _store = lock(&self.store);
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        let prev = pin.roster().ok_or(OnePassError::NotFound)?;
        let joined = lock(&self.joins).verified(&pin, &account.0);
        let next = next_roster(prev, &edit, signer.account, joined.as_ref(), now_secs())?;
        let before = prev.member(account);
        let after = next.member(account).ok_or(OnePassError::NotFound)?;
        Ok(FfiEditSummary {
            member_name: joined
                .as_ref()
                .map_or_else(|| id_hex(account), |j| j.display_name().to_owned()),
            device_count: u32::try_from(after.devices.len()).unwrap_or(u32::MAX),
            roles_before: before.map(|m| roles_of(m.roles)).unwrap_or_default(),
            roles_after: roles_of(after.roles),
            state_before: before.map(|m| (&m.state).into()),
            state_after: (&after.state).into(),
            allowed: check_transition(pin.lineage(), prev, &next, &signer.me).is_ok(),
        })
    }

    /// Signs `edit` (the candidate `summarize` shows) and writes it at
    /// roster seq + 1: refused by the core rules is `Integrity {
    /// org_role_denied }` with nothing written; a seq taken meanwhile is
    /// rebased once, then `Conflict`. The join feed is read first (an
    /// `Accept` needs the member's verified request: `NotFound`).
    ///
    /// Then the member's own org mailbox credential follows the roster
    /// (R29): `Manage` for Owner, Admin or UserManager, else `Write` on join
    /// requests only; Suspended `Read`; Removed revoked. Which credential
    /// (R38): an `Accept` grants and binds the key of the verified request
    /// in `access.bin`; later edits move that bound key (never a key a
    /// request names afterwards), and on a device that did not accept the
    /// member, the key its verified request names. Any failure there only
    /// clears `server_access_updated` (`update_member_access` retries). The
    /// link's credential, when this device issued the invitation, is
    /// revoked once the member's credential is granted, and by any
    /// `Remove` (best effort; a removed member that never dropped it loses
    /// it too). `NotFound` before `pin`.
    pub fn edit_roster(
        &self,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        edit: FfiRosterEdit,
        now: i64,
    ) -> Result<FfiEditOutcome, OnePassError> {
        let classical = Zeroizing::new(classical);
        let signer = Signer::of(&session, &classical, pq)?;
        let account = parse_id(edit.account_id())?;
        let mut store = lock(&self.store);
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        // A feed read failure keeps the requests read so far.
        let _ = self.poll_joins(&mut **store);
        let joined = lock(&self.joins).verified(&pin, &account.0);
        let (pin, (), over) = self.signed_edit_over(&mut **store, &signer, |prev| {
            Ok((
                next_roster(prev, &edit, signer.account, joined.as_ref(), now)?,
                (),
            ))
        })?;
        // Invited in the roster the edit was finally put over: a pin read
        // before may predate an accept made on another device (the rebase
        // then removes an Active member).
        let was_invited = over
            .member(account)
            .is_some_and(|m| m.state == MemberState::Invited);
        let mailbox = store.mailbox();
        let access = pin
            .roster()
            .and_then(|r| r.member(account))
            .map(|m| follow_access(mailbox, &self.state_dir, m, joined.as_ref(), was_invited))
            .unwrap_or_default();
        if access.granted || matches!(edit, FfiRosterEdit::Remove { .. }) {
            self.revoke_links(mailbox, account);
        }
        Ok(FfiEditOutcome {
            state: self.show(&pin),
            server_access_updated: access.updated,
        })
    }

    /// Makes the org mailbox access of `account_id` (32 hex) follow its
    /// entry in the pinned roster again, with no roster edit: the retry the
    /// app offers when an edit answered `server_access_updated: false` (R38
    /// (e)). Same rules as after `edit_roster`. True once the server holds
    /// that access. `NotFound` before `pin` or for an account not in the
    /// roster.
    pub fn update_member_access(&self, account_id: String) -> Result<bool, OnePassError> {
        let account = parse_id(&account_id)?;
        let mut store = lock(&self.store);
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        // The retry acts on the current roster: a pin read before may still
        // show a member another device removed since (R42).
        let pin = self.refreshed(&mut **store, &pin)?;
        let m = pin
            .roster()
            .and_then(|r| r.member(account))
            .ok_or(OnePassError::NotFound)?
            .clone();
        let _ = self.poll_joins(&mut **store);
        let joined = lock(&self.joins).verified(&pin, &account.0);
        let mailbox = store.mailbox();
        let access = follow_access(mailbox, &self.state_dir, &m, joined.as_ref(), false);
        if access.granted || matches!(m.state, MemberState::Removed { .. }) {
            self.revoke_links(mailbox, account);
        }
        Ok(access.updated)
    }

    /// The owner keyset sealed to this account opens with its KEM secret
    /// and holds this org's identity and audit keys. False when this
    /// account is no owner of the pinned head, or none is stored, or it
    /// does not open. `NotFound` before `pin`.
    pub fn owner_keyset_available(
        &self,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<bool, OnePassError> {
        let classical = Zeroizing::new(classical);
        let signer = Signer::of(&session, &classical, pq)?;
        let mut store = lock(&self.store);
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        if !pin
            .head()
            .owners
            .iter()
            .any(|o| o.account_id == signer.account)
        {
            return Ok(false);
        }
        Ok(self
            .open_keyset(&mut **store, &session, &pin, signer.account)?
            .is_some())
    }

    /// Changes the owners to `owners` (32 hex account ids). Quorum is
    /// `n / 2 + 1` of the current owners (R10): this device alone meets it
    /// only when the pinned head has one owner, this account, on this
    /// device; else `Validation { field: "owners", reason: "quorum" }` and
    /// nothing is written. `owners` keeps this account (`Validation {
    /// owners }`): the follow-up roster is signed here as an owner. A new
    /// owner must be an Active member whose verified join request this
    /// client has read (its identity and full KEM key, checked against the
    /// roster's hashes; `Validation { owners }` or `NotFound`).
    ///
    /// Writes, in order: the owner keyset sealed to each new owner, the
    /// `OwnersChanged` lineage record (signed by the org identity and this
    /// device, roster checkpoint = the pinned roster), then the roster that
    /// mirrors the new owners (X9, X10). New owners' credentials get
    /// `Manage`, best effort. The pin is refreshed first; a failure after
    /// the lineage write leaves it written, and calling `set_owners` again
    /// (with the same set) completes it: when this device is a head owner,
    /// the pinned roster names an older org head and its `Owner` bits are
    /// not on the head's owners, that roster and the grants are written and
    /// nothing else; then a set other than the head's owners is
    /// `Validation { owners, "pending change" }` (the mirror stays written).
    /// The head's own owner set again changes nothing (no quorum needed).
    /// `NotFound` before `pin`.
    pub fn set_owners(
        &self,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        owners: Vec<String>,
        now: i64,
    ) -> Result<FfiOrgState, OnePassError> {
        let classical = Zeroizing::new(classical);
        let signer = Signer::of(&session, &classical, pq)?;
        let mut wanted = owners
            .iter()
            .map(|o| parse_id(o))
            .collect::<Result<Vec<_>, _>>()?;
        wanted.sort();
        wanted.dedup();
        let mut store = lock(&self.store);
        let pin = self.load()?.ok_or(OnePassError::NotFound)?;
        // The newest head first: a lineage written by an earlier call whose
        // roster write failed is completed here, never changed again.
        let pin = self.refreshed(&mut **store, &pin)?;
        let head = pin.head().clone();
        let fpr = signer.me.fingerprint();
        let owner_here = head
            .owners
            .iter()
            .any(|o| o.account_id == signer.account && o.devices.contains(&fpr));
        let roster = pin.roster().ok_or(OnePassError::NotFound)?;
        let current: Vec<Id> = head.owners.iter().map(|o| o.account_id).collect();
        if owner_here && unmirrored(roster, &head) {
            let _ = self.poll_joins(&mut **store);
            let pin = self.mirror_and_grant(&mut **store, &signer, &head)?;
            if wanted != current {
                // The earlier change is completed; another one waits for a
                // new call (with the quorum the new head needs).
                return Err(validation("owners", "pending change"));
            }
            return Ok(self.show(&pin));
        }
        if wanted == current {
            // No change: nothing to sign.
            return Ok(self.show(&pin));
        }
        let sole = match head.owners.as_slice() {
            [o] => o.account_id == signer.account && o.devices.contains(&signer.me.fingerprint()),
            _ => false,
        };
        if !sole {
            return Err(validation("owners", "quorum"));
        }
        if !wanted.contains(&signer.account) {
            return Err(validation("owners", "keeps this account"));
        }
        let _ = self.poll_joins(&mut **store);
        let mut refs = Vec::new();
        let mut added = Vec::new();
        for id in wanted {
            if let Some(r) = head.owners.iter().find(|o| o.account_id == id) {
                refs.push(r.clone());
                continue;
            }
            let m = roster.member(id).ok_or(OnePassError::NotFound)?;
            if m.state != MemberState::Active {
                return Err(validation("owners", "not an active member"));
            }
            let joined = lock(&self.joins)
                .verified(&pin, &id.0)
                .ok_or(OnePassError::NotFound)?;
            let r = MemberRef {
                account_id: id,
                account_identity_pub: joined.account_identity_pub().clone(),
                account_kem_pub: joined.account_kem_pub().clone(),
                devices: m.devices.clone(),
            };
            refs.push(r.clone());
            added.push((r, joined));
        }
        let keyset = self
            .open_keyset(&mut **store, &session, &pin, signer.account)?
            .ok_or(OnePassError::NotFound)?;
        let body = OrgChangeBody {
            format: ORG_FORMAT,
            org_id: OrgId(self.org_id),
            generation: head.generation + 1,
            parent: head.hash,
            kind: OrgChangeKind::OwnersChanged {
                owners: refs,
                roster_checkpoint: RosterCheckpoint {
                    seq: roster.seq,
                    hash: roster.hash(),
                },
            },
            issued_at: now,
        };
        let record = sign_org_change(
            body,
            &keyset.secrets.identity,
            &[(&signer.me, &signer.keys)],
        )?;
        // The pinned lineage accepts it before anything is written.
        let next_head = pin.lineage().apply(&record)?.head().clone();
        for (r, _) in &added {
            let sealed = seal_org_keyset(&keyset, r.account_id, &r.account_kem_pub)?;
            store.put_owner_keyset(r.account_id.0, sealed.encode())?;
        }
        store.put_lineage(next_head.generation, record.encode())?;
        self.refreshed(&mut **store, &pin)?;
        let pin = self.mirror_and_grant(&mut **store, &signer, &next_head)?;
        Ok(self.show(&pin))
    }
}

/// What a failed `set_owners` leaves (the one state its resume cures): the
/// roster still names an older org head and the `Owner` bits are not on
/// exactly the head's owners. Only what `mirror_owners` writes is compared,
/// so any roster it wrote, or a head that moved without an owner change,
/// is not "unmirrored".
fn unmirrored(roster: &RosterBody, head: &OrgHeadInfo) -> bool {
    let owns = |a: Id| head.owners.iter().any(|o| o.account_id == a);
    let bits_follow = roster
        .members
        .iter()
        .all(|m| m.roles.contains(Role::Owner) == owns(m.account_id))
        && head
            .owners
            .iter()
            .all(|o| roster.member(o.account_id).is_some());
    roster.org_head != head.hash && !bits_follow
}

impl OrgClient {
    /// The roster that mirrors `head` (signed by this owner device), then
    /// `Manage` for the other head owners' own credentials (from their
    /// verified join requests read so far), best effort.
    fn mirror_and_grant(
        &self,
        store: &mut dyn OrgStoreApi,
        signer: &Signer,
        head: &OrgHeadInfo,
    ) -> Result<OrgPin, OnePassError> {
        let (pin, ()) =
            self.signed_edit(store, signer, |prev| Ok((mirror_owners(prev, head)?, ())))?;
        if let Some(r) = pin.roster() {
            let mut joins = lock(&self.joins);
            for o in head
                .owners
                .iter()
                .filter(|o| o.account_id != signer.account)
            {
                if let Some(m) = r.member(o.account_id) {
                    let joined = joins.verified(&pin, &o.account_id.0);
                    let _ =
                        follow_access(store.mailbox(), &self.state_dir, m, joined.as_ref(), false);
                }
            }
        }
        Ok(pin)
    }

    /// The owner keyset sealed to `account`, opened with the session's KEM
    /// secret and checked against the pinned lineage; `None` when none is
    /// stored or it does not open or match.
    fn open_keyset(
        &self,
        store: &mut dyn OrgStoreApi,
        session: &Session,
        pin: &OrgPin,
        account: Id,
    ) -> Result<Option<OrgKeyset>, OnePassError> {
        let Some(bytes) = store.owner_keyset(account.0)? else {
            return Ok(None);
        };
        let Ok(sealed) = SealedOrgKeyset::decode(&bytes) else {
            return Ok(None);
        };
        let org = OrgId(self.org_id);
        let keyset = session.with(|repo| {
            Ok(open_org_keyset(&sealed, org, account, &repo.account().keyset().kem).ok())
        })?;
        Ok(keyset.filter(|k| k.check_against(pin.lineage()).is_ok()))
    }
}

#[cfg(feature = "dev-fast-kdf")]
impl OrgClient {
    /// An org client over any org store: `OrgStore` over a `FakeMailbox`
    /// client, or `HostileOrgStore` (tests only, no TLS). `server_url`: what
    /// its join links name.
    #[doc(hidden)]
    pub fn with_store(
        store: Box<dyn OrgStoreApi + Send>,
        org_id: [u8; 16],
        state_dir: PathBuf,
        server_url: String,
    ) -> Arc<Self> {
        Self::build(store, org_id, state_dir, server_url)
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
