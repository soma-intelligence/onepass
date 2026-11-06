//! Moving a shared vault out of its owner's mailbox, and back to personal
//! (sharing spec 9.5, S9, decision 7, plan 2 ruling A-10, Task 12).
//!
//! The zone of a shared vault is keyed by the vault id, so the copy takes
//! a new vault id: the old zone and the new one live side by side until
//! every member moved.

use super::{Repository, Use};
use crate::contact::ContactLevel;
use crate::share::{
    InviteRecord, MembershipReason, MovedTo, Role, ShareAction, ShareState, SharedVaultInfo,
    accept_next, sign_membership,
};
use crate::store::{Record, RecordKind, RecordStore, Zone};
use crate::vault::Vault;
use crate::{Error, Id, Result, ValidationError};

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

impl<S: RecordStore> Repository<S> {
    /// Copy shared vault `vault_id` into a new shared vault under my own
    /// mailbox (spec 9.5, the owner leaves): I am a manager, not the
    /// owner. One new shared vault (a new vault id, me owner, generation
    /// 1, a `CreateZoneMailbox` of my own) gets every item of the old one
    /// (live, archived, trashed, same item ids). Once `set_zone_home` gave
    /// the new zone its mailbox, the members of the old vault held in my
    /// book are added with their roles, then a last `Rekey` body in the old
    /// zone points at the new home (`moved_to`). Returns the new vault.
    pub fn transfer_by_copy(&mut self, vault_id: Id, now: i64) -> Result<SharedVaultInfo> {
        let mut state = self.manager_state(vault_id)?;
        let me = self.me();
        if state.head.member(me.account_id).is_some_and(|m| m.owner) {
            return Err(refused("member", "owner"));
        }
        if state.moving_to.is_some() || state.head.moved_to.is_some() {
            return Err(refused("vault", "already moved"));
        }
        let old = self.open_shared(vault_id)?;
        let loaded = self.shared_served(&old, Use::Read)?;
        let mut items = Vec::with_capacity(loaded.records.len());
        for (_, rec) in &loaded.records {
            items.push(old.open_item(rec)?);
        }
        let personal = self.create_vault(old.meta.clone())?;
        let info = self.share_vault(&personal, now)?;
        let new = self.open_shared(info.vault_id)?;
        for mut item in items {
            item.vault_id = new.id;
            self.shared_save_item(&new, item)?;
        }
        state.moving_to = Some(new.id);
        self.store
            .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
        let state = self.store.share_state(new.id)?.ok_or(Error::NotFound)?;
        self.shared_info(&state, &new.meta.name)
    }

    /// The new zone of a transfer got its mailbox: add the members, then
    /// write the last body of the old zone. Members I cannot invite (not
    /// an `Active` contact of my book) stay behind on the old zone.
    pub(crate) fn finish_transfer(&mut self, new_id: Id, now: i64) -> Result<()> {
        let Some(mut old) = self
            .store
            .share_states()?
            .into_iter()
            .find(|s| s.moving_to == Some(new_id))
        else {
            return Ok(());
        };
        let now = now.max(old.head.issued_at);
        let me = self.me();
        let new_state = self.store.share_state(new_id)?.ok_or(Error::NotFound)?;
        for m in &old.head.members {
            if m.account_id == me.account_id || new_state.head.member(m.account_id).is_some() {
                continue;
            }
            let Some(c) = self.contact(m.account_id)? else {
                continue;
            };
            if !c.usable_for(ContactLevel::Link) {
                continue;
            }
            let role = if c.level == ContactLevel::Verified {
                m.role
            } else {
                Role::Read
            };
            self.add_member(new_id, m.account_id, role, now)?;
        }
        let home = self
            .zone_accesses()?
            .into_iter()
            .find(|a| a.target == crate::share::AccessTarget::Zone(Zone::Vault(new_id)))
            .and_then(|a| a.home)
            .ok_or(Error::NotFound)?;
        let mut body = old.head.next(me, MembershipReason::Rekey, now)?;
        body.moved_to = Some(MovedTo { owner: me, home });
        let signed = sign_membership(body, &self.account.keyset().signing)?;
        let next = accept_next(&old.head, &signed)?;
        let zone = old.zone;
        let expected = self
            .store
            .get_in(zone, RecordKind::Membership, old.vault_id)?
            .map(|r| r.version);
        old.advance(next.clone());
        old.moving_to = None;
        // My copy of the old zone goes once the last body is sent.
        old.leaving = true;
        self.store.put_all_zoned(
            vec![(
                zone,
                Record {
                    kind: RecordKind::Membership,
                    id: old.vault_id,
                    version: next.seq,
                    data: signed.encode(),
                },
                expected,
            )],
            vec![],
            None,
            std::slice::from_ref(&old),
        )
    }

    /// The pinned head of `state` says the vault moved (`moved_to`): join
    /// the new vault from the invite its new owner left in our contact
    /// zone, then let the old zone go (once the old owner deleted its
    /// mailbox, when that is me). No invite yet: nothing changes, the next
    /// follow tries again.
    pub(crate) fn follow_move(&mut self, vault_id: Id, now: i64) -> Result<()> {
        let Some(mut state) = self.store.share_state(vault_id)? else {
            return Ok(());
        };
        let Some(moved) = state.head.moved_to.clone() else {
            return Ok(());
        };
        if state.leaving {
            return Ok(());
        }
        let me = self.me();
        if moved.owner.account_id == me.account_id {
            return Ok(());
        }
        let Some(invite) = self.invite_for_home(&moved)? else {
            return Ok(());
        };
        self.accept_share_invite(invite, now)?;
        let i_own = state
            .head
            .member(me.account_id)
            .is_some_and(|m| m.owner && m.identity_id == me.identity_id);
        if i_own {
            state
                .actions
                .push(ShareAction::DeleteZoneMailbox { zone: state.zone });
        }
        state.leaving = true;
        // Nothing of mine goes to the old zone any more.
        let pending: Vec<(RecordKind, Id)> = self
            .store
            .zone_pending(state.zone)?
            .into_iter()
            .map(|r| (r.0, r.1))
            .collect();
        self.store.drop_zone_pending(state.zone, &pending)?;
        self.store
            .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
        self.finish_leave(vault_id)
    }

    /// The invite of `moved.owner` whose home is `moved.home`, checked as
    /// `share_invites` checks it, for a vault I did not join yet.
    fn invite_for_home(&mut self, moved: &MovedTo) -> Result<Option<Id>> {
        for zone in self.contact_zones()? {
            for rec in self.store.list_in(zone, RecordKind::ShareInvite)? {
                let Ok(InviteRecord::Vault(inv)) = InviteRecord::decode(&rec.data) else {
                    continue;
                };
                if inv.home != moved.home || inv.signer != moved.owner {
                    continue;
                }
                if self.checked_invite(zone, &rec).is_err()
                    || self.store.share_state(inv.vault_id)?.is_some()
                {
                    continue;
                }
                return Ok(Some(rec.id));
            }
        }
        Ok(None)
    }

    /// Stop sharing vault `vault_id` (spec 9.5): I am its only member. The
    /// items (live, archived, trashed, same item ids) go to a new personal
    /// vault under a new vault id (the vault list keeps the shared id
    /// deleted); the shared zone is erased here once the transport ran the
    /// queued `DeleteZoneMailbox`. Refused while another member is listed
    /// (`Validation("vault", "other members")`).
    pub fn stop_sharing(&mut self, vault_id: Id, now: i64) -> Result<Vault> {
        let _ = now;
        let mut state = self.manager_state(vault_id)?;
        let me = self.me();
        if state
            .head
            .members
            .iter()
            .any(|m| m.account_id != me.account_id)
        {
            return Err(refused("vault", "other members"));
        }
        let shared = self.open_shared(vault_id)?;
        let loaded = self.shared_served(&shared, Use::Read)?;
        let mut items = Vec::with_capacity(loaded.records.len());
        for (_, rec) in &loaded.records {
            items.push(shared.open_item(rec)?);
        }
        let personal = self.create_vault(shared.meta.clone())?;
        for mut item in items {
            item.vault_id = personal.id;
            self.save_item(&personal, item)?;
        }
        let pending: Vec<(RecordKind, Id)> = self
            .store
            .zone_pending(state.zone)?
            .into_iter()
            .map(|r| (r.0, r.1))
            .collect();
        self.store.drop_zone_pending(state.zone, &pending)?;
        state.leaving = true;
        state
            .actions
            .push(ShareAction::DeleteZoneMailbox { zone: state.zone });
        self.store
            .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
        Ok(personal)
    }
}

impl ShareState {
    /// A transfer or a stop waits for this mailbox step before the zone
    /// is erased here.
    pub(crate) fn waits_for_mailbox(&self) -> bool {
        self.actions.iter().any(|a| {
            matches!(
                a,
                ShareAction::RevokeCredential { .. } | ShareAction::DeleteZoneMailbox { .. }
            )
        })
    }
}
