//! What the core asks the transport to do on zone mailboxes (sharing spec
//! 13.3, 13.4; plan 4 runs them). Actions carry public keys and credential
//! ids only, never a seed.

use serde::{Deserialize, Serialize};

use super::{Role, ZoneRole};
use crate::Id;
use crate::contact::ContactLevel;
use crate::store::Zone;

/// The kind of child mailbox a zone lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneMailboxKind {
    Shared,
    Contact,
}

/// One step for the transport. The actions of one zone run in order: a
/// grant waits until the zone's mailbox exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareAction {
    CreateZoneMailbox {
        zone: Zone,
        kind: ZoneMailboxKind,
        owner_public_key: [u8; 32],
    },
    GrantCredential {
        zone: Zone,
        public_key: [u8; 32],
        role: ZoneRole,
        put_kinds: Option<[u8; 32]>,
    },
    SetCredentialRole {
        zone: Zone,
        credential_id: [u8; 16],
        role: ZoneRole,
        put_kinds: Option<[u8; 32]>,
    },
    RevokeCredential {
        zone: Zone,
        credential_id: [u8; 16],
    },
    DeleteZoneMailbox {
        zone: Zone,
    },
}

impl ShareAction {
    pub fn zone(&self) -> Zone {
        match self {
            ShareAction::CreateZoneMailbox { zone, .. }
            | ShareAction::GrantCredential { zone, .. }
            | ShareAction::SetCredentialRole { zone, .. }
            | ShareAction::RevokeCredential { zone, .. }
            | ShareAction::DeleteZoneMailbox { zone } => *zone,
        }
    }
}

/// One member of a shared vault as the screens show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberView {
    pub account_id: Id,
    /// The name of the local contact book, empty for this account or an
    /// account not in the book.
    pub name_local: String,
    pub role: Role,
    pub owner: bool,
    pub level: ContactLevel,
    /// The pinned contact's keys differ from the ones in the body.
    pub keys_changed: bool,
    pub key_pending: bool,
}

/// A shared vault as the screens show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedVaultInfo {
    pub vault_id: Id,
    pub name: String,
    pub role: Role,
    pub owner: bool,
    pub generation: u32,
    pub members: Vec<MemberView>,
    pub identity_pending: bool,
    pub mcp_hidden: bool,
}
