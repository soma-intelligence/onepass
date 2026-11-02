//! The local pinned state of one shared vault (sharing spec 7.2, 8.2, 10.2,
//! 12.3): the membership head this device accepted, its known ancestors,
//! the identities seen to rotate, and local settings. Kept in the device's
//! local metadata, never synced.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{MEMBERSHIP_HISTORY, MemberRef, MembershipBody, MembershipView, ShareAction};
use crate::lineage::decode_strict_with;
use crate::manifest::SeenManifest;
use crate::store::Zone;
use crate::{Error, Id, Result};

const BAD: Error = Error::InvalidFormat("share state");
/// Encoding version of `ShareState`.
pub const SHARE_STATE_VERSION: u8 = 1;

/// My own new identity, not yet adopted in this vault (spec 12.3, S24).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingIdentity {
    pub new_identity: MemberRef,
    pub since: i64,
}

/// What this device pins for one shared vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareState {
    pub version: u8,
    pub vault_id: Id,
    pub zone: Zone,
    pub head: MembershipBody,
    /// At most `MEMBERSHIP_HISTORY`, newest first.
    pub ancestors: Vec<MembershipBody>,
    /// A member identity seen to rotate, and the last membership seq this
    /// device accepted under it (plan 2 ruling A-12): a later body or
    /// manifest signed by that identity is refused.
    pub retired_signers: BTreeMap<MemberRef, u64>,
    pub identity_pending: Option<PendingIdentity>,
    /// Local only: hide this vault from the MCP server even when its meta
    /// allows it (spec 10.2).
    pub mcp_hidden: bool,
    /// Mailbox steps queued for the transport, in order, written in the
    /// same transaction as the change that needs them.
    pub actions: Vec<ShareAction>,
    /// The last shared manifest this device accepted (the personal vaults
    /// keep theirs in the device state).
    pub last_manifest: Option<SeenManifest>,
    /// The `meta_hash` that manifest committed to: a change needs a
    /// manager (spec 8.2 rule 4).
    pub last_meta: Option<[u8; 32]>,
}

impl ShareState {
    /// The state of a vault whose first body this device just accepted.
    pub fn new(zone: Zone, head: MembershipBody) -> ShareState {
        ShareState {
            version: SHARE_STATE_VERSION,
            vault_id: head.vault_id,
            zone,
            head,
            ancestors: Vec::new(),
            retired_signers: BTreeMap::new(),
            identity_pending: None,
            mcp_hidden: false,
            actions: Vec::new(),
            last_manifest: None,
            last_meta: None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("share state encodes")
    }

    /// Strict decoding: version, a shared zone, bodies of this vault,
    /// ancestors capped and strictly older than the head, newest first.
    pub fn decode(b: &[u8]) -> Result<ShareState> {
        let s: ShareState = decode_strict_with(b, BAD)?;
        let ordered = std::iter::once(&s.head)
            .chain(s.ancestors.iter())
            .collect::<Vec<_>>()
            .windows(2)
            .all(|w| w[0].seq > w[1].seq);
        if s.version != SHARE_STATE_VERSION
            || !s.zone.is_shared()
            || s.ancestors.len() > MEMBERSHIP_HISTORY
            || !ordered
            || s.head.vault_id != s.vault_id
            || s.ancestors.iter().any(|a| a.vault_id != s.vault_id)
        {
            return Err(BAD);
        }
        Ok(s)
    }

    pub fn view(&self) -> MembershipView<'_> {
        MembershipView {
            head: &self.head,
            ancestors: &self.ancestors,
        }
    }

    /// Pin `next` as the head; the old head becomes the newest ancestor and
    /// the oldest falls out past `MEMBERSHIP_HISTORY`.
    pub fn advance(&mut self, next: MembershipBody) {
        let old = std::mem::replace(&mut self.head, next);
        self.ancestors.insert(0, old);
        self.ancestors.truncate(MEMBERSHIP_HISTORY);
    }
}
