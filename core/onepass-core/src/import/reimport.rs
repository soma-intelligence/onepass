//! Importing into a vault that already holds an earlier import of the same
//! source: every imported item is matched with the vault item it stands
//! for, and that item is updated in place (same id, so its timeline,
//! favorite, tags and shares stay) instead of being added again.
//!
//! Only 1PUX and Credential Exchange imports are matched
//! (`matches_existing`); other formats add. An imported item matches, in
//! this order:
//! 1. the vault item carrying the same source tag (`SOURCE_TAG_PREFIX`);
//! 2. 1PUX only: the item an older import made without that tag: same
//!    title, same creation time, the source vault among its tags;
//! 3. the item with the same title, the same site and a compatible
//!    username (equal, or one of them blank);
//! 4. for an item holding a passkey (Credential Exchange): the login of the
//!    passkey's site and account.
//!
//! In every case the vault item's type must be the imported one, or the
//! fallback an older importer chose for it (Secure Note, or Password for a
//! Login). A fallback item is converted: it takes the imported content and
//! keeps its id, timeline, tags, favorite, color and icon (`Outcome::Fixed`).
//! An item of the same type is merged without losing anything: blank fields
//! are filled, missing passkeys, sign-in methods, addresses and tags are
//! added, and a value both sides hold is replaced only when the source
//! changed it after the vault did (the replaced password goes to the
//! history). Nothing to add is `Outcome::Unchanged`, and is not written.
//!
//! Nothing is ever deleted. A converted note is first copied, as it was,
//! into an archived item (`Plan::archived`), so its old content stays
//! reachable. Once the import is planned, exact duplicates that involve an
//! item of this import (same type, same site, same username, same password)
//! fold into one item through `duplicates::merge`: the others are archived
//! intact with a note. Near duplicates are left to the duplicates review.

use std::collections::{BTreeMap, HashMap, HashSet};

use time::OffsetDateTime;

use super::{Format, Import, is_source_tag};
use crate::id::Id;
use crate::model::{FieldValue, Item, ItemType, LoginMethod, PasswordHistoryEntry};
use crate::watchtower::host::host_of;

/// What a re-import does with one imported item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// New in the vault.
    Added,
    /// Updates a vault item of the same type: something added or changed.
    Fixed,
    /// A secure note (or password) an older import made instead of this
    /// item becomes it again, same id; the note as it was is archived.
    Converted,
    /// The vault item already holds everything: nothing is written.
    Unchanged,
}

/// One imported item ready for the vault, and what it does there.
#[derive(Debug, Clone)]
pub struct Planned {
    pub item: Item,
    pub outcome: Outcome,
}

/// Everything an import writes: the imported items (and the vault items
/// an exact duplicate folded into), then archived items (converted notes
/// as they were, folded duplicates). `Planned::outcome` of an `Unchanged`
/// item means it is not written.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub items: Vec<Planned>,
    /// Copies of the converted notes as they were, archived.
    pub archived_notes: Vec<Item>,
    /// Exact duplicates folded into another item, archived.
    pub archived_duplicates: Vec<Item>,
}

/// Counts of a plan, for the dry run shown before writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub added: u32,
    pub fixed: u32,
    pub converted: u32,
    pub unchanged: u32,
    pub archived_duplicates: u32,
}

impl Plan {
    pub fn counts(&self) -> Counts {
        let n = |o: Outcome| {
            u32::try_from(self.items.iter().filter(|p| p.outcome == o).count()).unwrap_or(u32::MAX)
        };
        Counts {
            added: n(Outcome::Added),
            fixed: n(Outcome::Fixed),
            converted: n(Outcome::Converted),
            unchanged: n(Outcome::Unchanged),
            archived_duplicates: u32::try_from(self.archived_duplicates.len()).unwrap_or(u32::MAX),
        }
    }

    /// Every item to save, in order: written imported items, then the
    /// archived ones.
    pub fn to_write(self) -> Vec<Item> {
        self.items
            .into_iter()
            .filter(|p| p.outcome != Outcome::Unchanged)
            .map(|p| p.item)
            .chain(self.archived_notes)
            .chain(self.archived_duplicates)
            .collect()
    }
}

/// Note appended to an archived copy of a converted note.
const REPLACED_NOTE: &str = "Remplacé à l'import par l'identifiant du même nom.";
/// Note appended to a folded exact duplicate (`duplicates::merge`).
const MERGED_NOTE: &str = "Doublon exact fusionné à l'import.";

const IMPORTED_SECTION: &str = "imported";

/// The items of `import` ready for `vault`, matched against `existing` (the
/// vault's items). New items get a new id; matched ones the id of their
/// vault item. The source folder is kept as a tag and "sign in with"
/// methods point at the final id of their account item.
pub fn reconcile(
    format: Format,
    import: Import,
    vault: Id,
    existing: &[Item],
    now: OffsetDateTime,
) -> Plan {
    let mut archived_notes: Vec<Item> = Vec::new();
    let mut claimed: HashSet<Id> = HashSet::new();
    let mut ids: HashMap<Id, Id> = HashMap::new();
    let mut out: Vec<Planned> = Vec::with_capacity(import.items.len());
    let legacy = format == Format::OnePasswordPux;
    for it in import.items {
        let mut item = it.item;
        let folder = it
            .folder
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(str::to_owned);
        if let Some(folder) = &folder
            && !item.tags.iter().any(|t| t == folder)
        {
            item.tags.push(folder.clone());
        }
        let found = if matches_existing(format) {
            find(&item, folder.as_deref(), existing, &claimed, legacy)
        } else {
            None
        };
        let provisional = item.id;
        let planned = match found {
            Some(e) => {
                claimed.insert(e.id);
                let p = merge(e, item);
                if p.outcome == Outcome::Converted {
                    archived_notes.push(archived_copy(e, vault, now));
                }
                p
            }
            None => {
                item.id = Id::new();
                item.vault_id = vault;
                Planned {
                    item,
                    outcome: Outcome::Added,
                }
            }
        };
        if provisional != Id([0; 16]) {
            ids.insert(provisional, planned.item.id);
        }
        out.push(planned);
    }
    for p in &mut out {
        let mut changed = false;
        for m in &mut p.item.login_methods {
            if let LoginMethod::Provider { account, .. } = m
                && let Some(final_id) = ids.get(account)
                && account != final_id
            {
                *account = *final_id;
                changed = true;
            }
        }
        // A provisional account id remapped to the id the vault already
        // stores is no change.
        if changed
            && p.outcome == Outcome::Unchanged
            && let Some(e) = existing.iter().find(|e| e.id == p.item.id)
            && e.login_methods != p.item.login_methods
        {
            p.outcome = Outcome::Fixed;
        }
    }
    let mut plan = Plan {
        items: out,
        archived_notes,
        archived_duplicates: Vec::new(),
    };
    if matches_existing(format) {
        fold_exact_duplicates(&mut plan, existing, now);
    }
    plan
}

/// The vault item `e` as it was, under a new id, archived, with a note
/// saying what replaced it.
fn archived_copy(e: &Item, vault: Id, now: OffsetDateTime) -> Item {
    let mut c = e.clone();
    c.id = Id::new();
    c.vault_id = vault;
    c.archived = true;
    c.favorite = false;
    c.tags.retain(|t| !is_source_tag(t));
    c.events.clear();
    c.usage.clear();
    c.usage_forgotten.clear();
    if !c.notes.is_empty() {
        c.notes.push('\n');
    }
    c.notes.push_str(REPLACED_NOTE);
    c.updated_at = now;
    c
}

/// The secret of an item for exact duplicates: its password.
fn password(item: &Item) -> Option<&str> {
    item.sections
        .iter()
        .filter(|s| s.id != IMPORTED_SECTION)
        .flat_map(|s| &s.fields)
        .find_map(|f| match (&f.id[..], &f.value) {
            ("password", FieldValue::Password(p)) if !p.trim().is_empty() => Some(p.as_str()),
            _ => None,
        })
}

/// Same type, same first site, same username, same password.
fn exact_key(item: &Item) -> Option<(ItemType, String, String, String)> {
    if item.archived || item.trashed_at.is_some() || item.is_profile() || item.is_pending() {
        return None;
    }
    if !matches!(item.item_type, ItemType::Login | ItemType::Password) {
        return None;
    }
    let host = hosts(item).into_iter().next()?;
    Some((
        item.item_type,
        host,
        username(item),
        password(item)?.to_owned(),
    ))
}

/// Folds the exact duplicates that involve an item this import writes.
/// The primary is the oldest vault item of the group (else the first
/// imported one); the others are archived by `duplicates::merge`. A group
/// with attachments on a folded item is left to the duplicates review.
fn fold_exact_duplicates(plan: &mut Plan, existing: &[Item], now: OffsetDateTime) {
    // The vault as it will be: planned items over the existing ones.
    let planned: HashMap<Id, usize> = plan
        .items
        .iter()
        .enumerate()
        .map(|(i, p)| (p.item.id, i))
        .collect();
    let mut view: Vec<(Item, Option<usize>)> = existing
        .iter()
        .filter(|e| !planned.contains_key(&e.id))
        .map(|e| (e.clone(), None))
        .collect();
    view.extend(
        plan.items
            .iter()
            .enumerate()
            .map(|(i, p)| (p.item.clone(), Some(i))),
    );
    let mut groups: BTreeMap<(String, String, String, String), Vec<usize>> = BTreeMap::new();
    for (vi, (item, _)) in view.iter().enumerate() {
        if let Some((t, h, u, p)) = exact_key(item) {
            groups
                .entry((format!("{t:?}"), h, u, p))
                .or_default()
                .push(vi);
        }
    }
    let mut drop: HashSet<usize> = HashSet::new();
    for members in groups.into_values() {
        if members.len() < 2 {
            continue;
        }
        let touched = members.iter().any(|vi| {
            view.get(*vi)
                .and_then(|(_, p)| *p)
                .and_then(|i| plan.items.get(i))
                .is_some_and(|p| p.outcome != Outcome::Unchanged)
        });
        if !touched {
            continue;
        }
        // Primary: an item already in the vault, the oldest; else the first.
        let is_new = |vi: &usize| {
            view.get(*vi)
                .and_then(|(_, p)| *p)
                .and_then(|i| plan.items.get(i))
                .is_some_and(|p| p.outcome == Outcome::Added)
        };
        let Some(primary_vi) = members
            .iter()
            .filter(|vi| !is_new(vi))
            .min_by_key(|vi| view.get(**vi).map(|(it, _)| it.created_at))
            .or_else(|| members.first())
            .copied()
        else {
            continue;
        };
        let Some((primary, primary_plan)) = view.get(primary_vi).cloned() else {
            continue;
        };
        let others: Vec<&Item> = members
            .iter()
            .filter(|vi| **vi != primary_vi)
            .filter_map(|vi| view.get(*vi).map(|(it, _)| it))
            .collect();
        let mut m = crate::duplicates::merge(&primary, &others, MERGED_NOTE, now);
        if !m.attachments.is_empty() {
            continue;
        }
        // The primary answers for the folded items' sources from now on.
        for a in &mut m.archived {
            for t in a.tags.iter().filter(|t| is_source_tag(t)) {
                if !m.merged.tags.contains(t) {
                    m.merged.tags.push(t.clone());
                }
            }
            a.tags.retain(|t| !is_source_tag(t));
        }
        match primary_plan.and_then(|i| plan.items.get_mut(i)) {
            Some(p) => {
                if p.item != m.merged {
                    p.item = m.merged;
                    if p.outcome == Outcome::Unchanged {
                        p.outcome = Outcome::Fixed;
                    }
                }
            }
            None => plan.items.push(Planned {
                item: m.merged,
                outcome: Outcome::Fixed,
            }),
        }
        for vi in members.iter().filter(|vi| **vi != primary_vi) {
            if let Some(i) = view.get(*vi).and_then(|(_, p)| *p) {
                drop.insert(i);
            }
        }
        plan.archived_duplicates.extend(m.archived);
    }
    if !drop.is_empty() {
        let items = std::mem::take(&mut plan.items);
        plan.items = items
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !drop.contains(i))
            .map(|(_, p)| p)
            .collect();
    }
}

/// Formats whose re-import updates the vault items it made: 1PUX and
/// Credential Exchange, which describe whole items. Elsewhere (CSV and the
/// like) a second import adds, as before.
pub fn matches_existing(format: Format) -> bool {
    matches!(format, Format::OnePasswordPux | Format::CredentialExchange)
}

/// The source tag of an item, if any.
fn source_tag(item: &Item) -> Option<&str> {
    item.tags
        .iter()
        .find(|t| is_source_tag(t))
        .map(String::as_str)
}

/// `onepass:src:1pux:` of `onepass:src:1pux:v/i`.
fn source_kind(tag: &str) -> &str {
    let rest = tag.get(super::SOURCE_TAG_PREFIX.len()..).unwrap_or("");
    match rest.find(':') {
        Some(i) => tag
            .get(..super::SOURCE_TAG_PREFIX.len() + i + 1)
            .unwrap_or(tag),
        None => tag,
    }
}

/// The vault item is another item of the same source: it carries a source
/// tag of the same kind that differs.
fn other_source_item(e: &Item, item: &Item) -> bool {
    let Some(mine) = source_tag(item) else {
        return false;
    };
    let kind = source_kind(mine);
    let theirs: Vec<&String> = e
        .tags
        .iter()
        .filter(|t| is_source_tag(t) && source_kind(t) == kind)
        .collect();
    !theirs.is_empty() && !theirs.iter().any(|t| *t == mine)
}

/// An archived item (an archived copy of a converted note among them) is
/// never converted.
fn compatible_type(e: &Item, item: &Item) -> bool {
    e.item_type == item.item_type
        || (!e.archived
            && (e.item_type == ItemType::SecureNote
                || (e.item_type == ItemType::Password && item.item_type == ItemType::Login)))
}

fn username(item: &Item) -> String {
    item.sections
        .iter()
        .filter(|s| s.id != IMPORTED_SECTION)
        .flat_map(|s| &s.fields)
        .find(|f| f.id == "username")
        .and_then(|f| match &f.value {
            FieldValue::Text(s) | FieldValue::Email(s) => Some(s.trim().to_lowercase()),
            _ => None,
        })
        .unwrap_or_default()
}

fn hosts(item: &Item) -> Vec<String> {
    item.urls
        .iter()
        .filter_map(|u| host_of(&u.url))
        .map(|h| h.trim_start_matches("www.").to_lowercase())
        .collect()
}

fn same_title(a: &Item, b: &Item) -> bool {
    a.title.trim().to_lowercase() == b.title.trim().to_lowercase()
}

/// Equal, or one of them blank.
fn users_fit(a: &str, b: &str) -> bool {
    a.is_empty() || b.is_empty() || a == b
}

fn passkey_list(item: &Item) -> Vec<&crate::model::PasskeyCredential> {
    item.sections
        .iter()
        .filter(|s| s.id != IMPORTED_SECTION)
        .flat_map(|s| &s.fields)
        .filter_map(|f| match &f.value {
            FieldValue::Passkey(p) => Some(p),
            _ => None,
        })
        .collect()
}

fn find<'a>(
    item: &Item,
    folder: Option<&str>,
    existing: &'a [Item],
    claimed: &HashSet<Id>,
    legacy: bool,
) -> Option<&'a Item> {
    let open: Vec<&Item> = existing
        .iter()
        .filter(|e| e.trashed_at.is_none() && !claimed.contains(&e.id) && !e.is_profile())
        .collect();
    if let Some(tag) = source_tag(item)
        && let Some(e) = open.iter().find(|e| e.tags.iter().any(|t| t == tag))
    {
        return Some(e);
    }
    let candidates: Vec<&Item> = open
        .into_iter()
        .filter(|e| compatible_type(e, item) && !other_source_item(e, item))
        .collect();
    if legacy
        && let Some(e) = candidates.iter().find(|e| {
            same_title(e, item)
                && e.created_at.unix_timestamp() == item.created_at.unix_timestamp()
                && folder.is_none_or(|f| e.tags.iter().any(|t| t == f))
        })
    {
        return Some(e);
    }
    let user = username(item);
    let item_hosts = hosts(item);
    // Without an address, only an item of the same type matches: a secure
    // note of the same title is not taken for a broken login unless the
    // site and the source folder say so.
    let same_site = |e: &Item| {
        let h = hosts(e);
        if e.item_type == item.item_type && h.is_empty() && item_hosts.is_empty() {
            return true;
        }
        h.iter().any(|x| item_hosts.contains(x))
            && (e.item_type == item.item_type
                || folder.is_none_or(|f| e.tags.iter().any(|t| t == f)))
    };
    let by_site: Vec<&Item> = candidates
        .iter()
        .copied()
        .filter(|e| same_title(e, item) && same_site(e) && users_fit(&username(e), &user))
        .collect();
    if let Some(e) = by_site
        .iter()
        .find(|e| !user.is_empty() && username(e) == user)
        .or_else(|| by_site.first())
    {
        return Some(e);
    }
    // A passkey: the login of its site and account.
    let keys = passkey_list(item);
    let first = keys.first()?;
    let rp = first.rp_id.trim().to_lowercase();
    if rp.is_empty() {
        return None;
    }
    let account = if first.user_name.trim().is_empty() {
        user
    } else {
        first.user_name.trim().to_lowercase()
    };
    let by_rp: Vec<&Item> = candidates
        .into_iter()
        .filter(|e| {
            e.item_type == ItemType::Login
                && hosts(e)
                    .iter()
                    .any(|h| *h == rp || h.ends_with(&format!(".{rp}")))
                && users_fit(&username(e), &account)
        })
        .collect();
    by_rp
        .iter()
        .find(|e| !account.is_empty() && username(e) == account)
        .or_else(|| by_rp.iter().find(|e| same_title(e, item)))
        .or_else(|| by_rp.first())
        .copied()
}

/// `item` merged into the vault item `e`.
fn merge(e: &Item, item: Item) -> Planned {
    if e.item_type != item.item_type {
        return Planned {
            item: convert(e, item),
            outcome: Outcome::Converted,
        };
    }
    let mut m = e.clone();
    let source_newer = item.updated_at > e.updated_at;
    // Fields of the template sections.
    for f in item
        .sections
        .iter()
        .filter(|s| s.id != IMPORTED_SECTION)
        .flat_map(|s| &s.fields)
    {
        if is_blank(&f.value) {
            continue;
        }
        if let FieldValue::Passkey(p) = &f.value {
            add_passkey(&mut m, f, p);
            continue;
        }
        let Some(g) = m
            .sections
            .iter_mut()
            .filter(|s| s.id != IMPORTED_SECTION)
            .flat_map(|s| s.fields.iter_mut())
            .find(|g| g.id == f.id && g.kind == f.kind)
        else {
            continue;
        };
        if is_blank(&g.value) {
            g.value = f.value.clone();
        } else if g.value != f.value && source_newer {
            if let FieldValue::Password(old) = &g.value
                && !old.is_empty()
            {
                m.password_history.push(PasswordHistoryEntry {
                    value: old.clone(),
                    replaced_at: item.updated_at,
                });
            }
            g.value = f.value.clone();
        }
    }
    if m.notes.trim().is_empty() && !item.notes.trim().is_empty() {
        m.notes.clone_from(&item.notes);
    }
    for u in &item.urls {
        if !m.urls.iter().any(|v| v.url == u.url) {
            let mut u = u.clone();
            u.primary = m.urls.is_empty();
            m.urls.push(u);
        }
    }
    for t in &item.tags {
        if !m.tags.contains(t) {
            m.tags.push(t.clone());
        }
    }
    merge_methods(&mut m, &item.login_methods);
    for h in &item.password_history {
        if !m.password_history.iter().any(|x| x.value == h.value) {
            m.password_history.push(h.clone());
        }
    }
    let outcome = if m == *e {
        Outcome::Unchanged
    } else {
        m.updated_at = m.updated_at.max(item.updated_at);
        Outcome::Fixed
    };
    Planned { item: m, outcome }
}

/// A fallback item (secure note, password) becomes the imported item,
/// keeping what the vault added to it.
fn convert(e: &Item, mut item: Item) -> Item {
    item.id = e.id;
    item.vault_id = e.vault_id;
    item.events.clone_from(&e.events);
    item.usage.clone_from(&e.usage);
    item.usage_forgotten.clone_from(&e.usage_forgotten);
    item.favorite |= e.favorite;
    if item.color.is_none() {
        item.color.clone_from(&e.color);
    }
    if item.custom_icon.is_none() {
        item.custom_icon.clone_from(&e.custom_icon);
    }
    item.created_at = e.created_at.min(item.created_at);
    item.updated_at = item.updated_at.max(e.updated_at);
    for t in &e.tags {
        if !item.tags.contains(t) {
            item.tags.push(t.clone());
        }
    }
    for h in &e.password_history {
        if !item.password_history.iter().any(|x| x.value == h.value) {
            item.password_history.push(h.clone());
        }
    }
    item
}

fn is_blank(v: &FieldValue) -> bool {
    match v {
        FieldValue::Empty => true,
        FieldValue::Text(s)
        | FieldValue::Email(s)
        | FieldValue::Url(s)
        | FieldValue::Phone(s)
        | FieldValue::Menu(s) => s.trim().is_empty(),
        FieldValue::Password(s) | FieldValue::Concealed(s) | FieldValue::Otp(s) => {
            s.trim().is_empty()
        }
        _ => false,
    }
}

/// Adds the passkey unless one with its credential id is there: into the
/// first blank passkey field, else after the last one.
fn add_passkey(m: &mut Item, f: &crate::model::Field, p: &crate::model::PasskeyCredential) {
    if passkey_list(m)
        .iter()
        .any(|q| q.credential_id == p.credential_id)
    {
        return;
    }
    let mut last: Option<(usize, usize)> = None;
    for (si, s) in m.sections.iter_mut().enumerate() {
        if s.id == IMPORTED_SECTION {
            continue;
        }
        for (fi, g) in s.fields.iter_mut().enumerate() {
            if g.id == f.id && g.kind == f.kind {
                if is_blank(&g.value) {
                    g.value = f.value.clone();
                    return;
                }
                last = Some((si, fi));
            }
        }
    }
    let Some((si, fi)) = last else {
        return;
    };
    if let Some(s) = m.sections.get_mut(si)
        && let Some(g) = s.fields.get(fi)
    {
        let mut copy = g.clone();
        copy.value = f.value.clone();
        s.fields.insert(fi + 1, copy);
    }
    if !m.login_methods.contains(&LoginMethod::Passkey) {
        m.login_methods.push(LoginMethod::Passkey);
    }
}

/// Adds the sign-in methods `m` lacks. A provider it already has keeps its
/// account item, or takes the imported one when it had none.
fn merge_methods(m: &mut Item, methods: &[LoginMethod]) {
    for method in methods {
        match method {
            LoginMethod::Provider {
                provider, account, ..
            } => {
                let mine = m.login_methods.iter_mut().find_map(|x| match x {
                    LoginMethod::Provider {
                        provider: p,
                        account: a,
                        ..
                    } if p == provider => Some(a),
                    _ => None,
                });
                match mine {
                    Some(a) if *a == Id([0; 16]) => *a = *account,
                    Some(_) => {}
                    None => m.login_methods.push(method.clone()),
                }
            }
            other => {
                if !m.login_methods.contains(other) {
                    m.login_methods.push(other.clone());
                }
            }
        }
    }
    // A login that signs in several ways lists its password first.
    let has_password = m
        .sections
        .iter()
        .filter(|s| s.id != IMPORTED_SECTION)
        .flat_map(|s| &s.fields)
        .any(|f| f.id == "password" && !is_blank(&f.value));
    if has_password
        && !m.login_methods.is_empty()
        && !m.login_methods.contains(&LoginMethod::Password)
    {
        m.login_methods.insert(0, LoginMethod::Password);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use time::OffsetDateTime;
    use zip::write::{SimpleFileOptions, ZipWriter};

    use super::*;
    use crate::model::{EventKind, Provider, new_item, validate};

    const PUX: &[u8] = include_bytes!("../../tests/fixtures/import/1pux-sign-in-with.data.json");
    const CXF: &[u8] = include_bytes!("../../tests/fixtures/import/cxf-1password-passkeys.json");

    fn pux() -> Import {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file("export.data", SimpleFileOptions::default())
            .unwrap();
        w.write_all(PUX).unwrap();
        let bytes = w.finish().unwrap().into_inner();
        super::super::parse(Format::OnePasswordPux, &bytes).unwrap()
    }

    fn cxf() -> Import {
        super::super::parse(Format::CredentialExchange, CXF).unwrap()
    }

    fn vault() -> Id {
        Id([7; 16])
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()
    }

    /// (added, fixed + converted, unchanged).
    fn counts(plan: &Plan) -> (u32, u32, u32) {
        let c = plan.counts();
        (c.added, c.fixed + c.converted, c.unchanged)
    }

    /// The vault an older importer left: every login without a username or
    /// password became a secure note (title, addresses, creation time and
    /// source folder kept, no source tag), the others stayed logins. The
    /// owner then starred one, tagged one and the timeline recorded it.
    fn legacy_vault() -> Vec<Item> {
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        pux()
            .items
            .into_iter()
            .map(|it| {
                let src = it.item;
                let broken = src.item_type == ItemType::Login
                    && (src
                        .login_methods
                        .iter()
                        .any(|m| matches!(m, LoginMethod::Provider { .. }))
                        || src.title == "WebAuthn demo");
                let mut item = if broken {
                    let mut n = new_item(ItemType::SecureNote, vault(), &src.title);
                    n.field_mut("content").unwrap().value =
                        FieldValue::Text(format!("{{\"ssoLogin\":\"{}\"}}", src.title));
                    n.urls.clone_from(&src.urls);
                    n.created_at = src.created_at;
                    n.updated_at = src.updated_at;
                    n
                } else {
                    let mut l = src.clone();
                    l.id = Id::new();
                    l.vault_id = vault();
                    l
                };
                item.tags = src
                    .tags
                    .iter()
                    .filter(|t| !is_source_tag(t))
                    .cloned()
                    .collect();
                item.tags.push("Personal".into());
                if item.title == "Notion" {
                    item.favorite = true;
                    item.tags.push("mine".into());
                    item.record(
                        at,
                        EventKind::Imported {
                            format: "1pux".into(),
                        },
                    );
                }
                item
            })
            .collect()
    }

    fn by<'a>(plan: &'a Plan, title: &str) -> &'a Planned {
        plan.items.iter().find(|p| p.item.title == title).unwrap()
    }

    /// The vault after the plan is written.
    fn written(plan: &Plan) -> Vec<Item> {
        plan.clone()
            .to_write()
            .into_iter()
            .chain(
                plan.items
                    .iter()
                    .filter(|p| p.outcome == Outcome::Unchanged)
                    .map(|p| p.item.clone()),
            )
            .collect()
    }

    fn passkeys(item: &Item) -> Vec<crate::model::PasskeyCredential> {
        passkey_list(item).into_iter().cloned().collect()
    }

    #[test]
    fn broken_secure_notes_become_logins_in_place() {
        let existing = legacy_vault();
        let notion_before = existing
            .iter()
            .find(|e| e.title == "Notion")
            .unwrap()
            .clone();
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &existing, now());
        assert_eq!(plan.items.len(), existing.len());
        // Every source item found its vault item: nothing added.
        assert_eq!(counts(&plan).0, 0, "no duplicate");
        let ids: HashSet<Id> = existing.iter().map(|e| e.id).collect();
        assert!(plan.items.iter().all(|p| ids.contains(&p.item.id)));
        for title in [
            "Notion",
            "Figma",
            "TestFlight",
            "Azure DevOps",
            "Instagram",
            "Internal Wiki",
            "Gist mirror",
            "WebAuthn demo",
        ] {
            let p = by(&plan, title);
            assert_eq!(p.outcome, Outcome::Converted, "{title}");
            assert_eq!(p.item.item_type, ItemType::Login, "{title}");
            validate(&p.item).unwrap();
        }
        let notion = &by(&plan, "Notion").item;
        assert_eq!(
            notion.id, notion_before.id,
            "same id: shares and links stay"
        );
        assert_eq!(notion.events, notion_before.events, "timeline kept");
        assert!(notion.favorite);
        assert!(notion.tags.contains(&"mine".to_owned()));
        // The provider points at the final id of the Google item (its vault id).
        let google = existing.iter().find(|e| e.title == "Google").unwrap().id;
        assert!(notion.login_methods.iter().any(|m| matches!(
            m,
            LoginMethod::Provider { provider: Provider::Google, account, .. } if *account == google
        )));
        assert!(notion.sections.iter().all(|s| s.id != IMPORTED_SECTION));
        // Nothing deleted: every converted note is kept, archived, as it was.
        assert_eq!(plan.archived_notes.len(), 8);
        assert_eq!(plan.counts().converted, 8);
        let copy = plan
            .archived_notes
            .iter()
            .find(|n| n.title == "Notion")
            .unwrap();
        assert!(copy.archived);
        assert_eq!(copy.item_type, ItemType::SecureNote);
        assert_ne!(copy.id, notion_before.id);
        assert_eq!(copy.field("content"), notion_before.field("content"));
        assert!(copy.notes.contains(REPLACED_NOTE));
    }

    #[test]
    fn importing_again_changes_nothing() {
        let first = reconcile(
            Format::OnePasswordPux,
            pux(),
            vault(),
            &legacy_vault(),
            now(),
        );
        let vault_now = written(&first);
        let again = reconcile(Format::OnePasswordPux, pux(), vault(), &vault_now, now());
        assert_eq!(
            counts(&again),
            (0, 0, u32::try_from(again.items.len()).unwrap())
        );
        assert!(
            again.archived_notes.is_empty(),
            "an archived copy is never converted again"
        );
        assert!(again.archived_duplicates.is_empty());
        let ids: HashSet<Id> = vault_now.iter().map(|e| e.id).collect();
        assert!(again.items.iter().all(|p| ids.contains(&p.item.id)));
    }

    #[test]
    fn fresh_vault_adds_everything() {
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &[], now());
        let n = u32::try_from(plan.items.len()).unwrap();
        assert_eq!(counts(&plan), (n, 0, 0));
        assert!(plan.items.iter().all(|p| p.item.vault_id == vault()));
        let google = by(&plan, "Google").item.id;
        assert!(
            by(&plan, "Notion")
                .item
                .login_methods
                .iter()
                .any(|m| matches!(
                    m,
                    LoginMethod::Provider { account, .. } if *account == google
                ))
        );
    }

    #[test]
    fn credential_exchange_passkeys_join_their_logins() {
        let vault_now = written(&reconcile(
            Format::OnePasswordPux,
            pux(),
            vault(),
            &[],
            now(),
        ));
        let plan = reconcile(
            Format::CredentialExchange,
            cxf(),
            vault(),
            &vault_now,
            now(),
        );
        assert_eq!(counts(&plan), (0, 2, 0), "no new item for a passkey");
        let demo_id = vault_now
            .iter()
            .find(|e| e.title == "WebAuthn demo")
            .unwrap()
            .id;
        let dev_id = vault_now
            .iter()
            .find(|e| e.title == "Dev account")
            .unwrap()
            .id;
        let demo = plan.items.iter().find(|p| p.item.id == demo_id).unwrap();
        let keys = passkeys(&demo.item);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].rp_id, "webauthn.example.com");
        assert_eq!(keys[0].credential_id, vec![1, 2, 3, 4]);
        assert_eq!(keys[0].user_handle, b"user1".to_vec());
        assert_eq!(keys[0].private_key.as_slice(), b"keyblo");
        assert!(demo.item.login_methods.contains(&LoginMethod::Passkey));
        validate(&demo.item).unwrap();
        // Matched by site and account, whatever the title ("GitHub" here).
        let dev = plan.items.iter().find(|p| p.item.id == dev_id).unwrap();
        assert_eq!(dev.item.title, "Dev account");
        let keys = passkeys(&dev.item);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].rp_id, "github.com");
        assert_eq!(
            dev.item.login_methods,
            vec![LoginMethod::Password, LoginMethod::Passkey]
        );
        // And once more: everything is there already.
        let vault_after: Vec<Item> = vault_now
            .iter()
            .map(|e| {
                plan.items
                    .iter()
                    .find(|p| p.item.id == e.id)
                    .map_or_else(|| e.clone(), |p| p.item.clone())
            })
            .collect();
        let again = reconcile(
            Format::CredentialExchange,
            cxf(),
            vault(),
            &vault_after,
            now(),
        );
        assert_eq!(counts(&again), (0, 0, 2));
    }

    #[test]
    fn a_value_changed_in_the_vault_after_the_export_wins() {
        let mut vault_now = written(&reconcile(
            Format::OnePasswordPux,
            pux(),
            vault(),
            &[],
            now(),
        ));
        let google = vault_now.iter_mut().find(|e| e.title == "Google").unwrap();
        google.field_mut("password").unwrap().value =
            FieldValue::Password(zeroize::Zeroizing::new("Changed-In-OnePass".into()));
        google.updated_at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &vault_now, now());
        let g = by(&plan, "Google");
        assert_eq!(g.outcome, Outcome::Unchanged);
        assert!(matches!(
            &g.item.field("password").unwrap().value,
            FieldValue::Password(p) if p.as_str() == "Changed-In-OnePass"
        ));
    }

    #[test]
    fn a_value_changed_in_the_source_later_wins_and_keeps_history() {
        let mut vault_now = written(&reconcile(
            Format::OnePasswordPux,
            pux(),
            vault(),
            &[],
            now(),
        ));
        let google = vault_now.iter_mut().find(|e| e.title == "Google").unwrap();
        google.field_mut("password").unwrap().value =
            FieldValue::Password(zeroize::Zeroizing::new("Older-Password".into()));
        google.updated_at = OffsetDateTime::from_unix_timestamp(1_500_000_000).unwrap();
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &vault_now, now());
        let g = by(&plan, "Google");
        assert_eq!(g.outcome, Outcome::Fixed);
        assert!(matches!(
            &g.item.field("password").unwrap().value,
            FieldValue::Password(p) if p.as_str() == "Google-Invented-1"
        ));
        assert!(
            g.item
                .password_history
                .iter()
                .any(|h| h.value.as_str() == "Older-Password")
        );
    }

    #[test]
    fn a_note_of_the_same_title_elsewhere_is_left_alone() {
        let mut note = new_item(ItemType::SecureNote, vault(), "Notion");
        note.field_mut("content").unwrap().value = FieldValue::Text("my own note".into());
        let plan = reconcile(
            Format::OnePasswordPux,
            pux(),
            vault(),
            &[note.clone()],
            now(),
        );
        let notion = by(&plan, "Notion");
        assert_eq!(notion.outcome, Outcome::Added);
        assert_ne!(notion.item.id, note.id);
    }

    #[test]
    fn other_formats_always_add() {
        let existing = written(&reconcile(
            Format::OnePasswordPux,
            pux(),
            vault(),
            &[],
            now(),
        ));
        let mut csv = pux();
        for it in &mut csv.items {
            it.item.tags.retain(|t| !is_source_tag(t));
        }
        let plan = reconcile(Format::ChromeCsv, csv, vault(), &existing, now());
        assert_eq!(counts(&plan).1 + counts(&plan).2, 0);
    }

    #[test]
    fn exact_duplicates_fold_into_one_and_are_archived() {
        // The vault already holds the Google login, saved by hand (no source
        // tag, another title, older): same site, username and password.
        let first = written(&reconcile(
            Format::OnePasswordPux,
            pux(),
            vault(),
            &[],
            now(),
        ));
        let mut mine = first.iter().find(|e| e.title == "Google").unwrap().clone();
        mine.id = Id::new();
        mine.title = "Gmail".into();
        mine.tags.clear();
        mine.created_at = OffsetDateTime::from_unix_timestamp(1_500_000_000).unwrap();
        let plan = reconcile(
            Format::OnePasswordPux,
            pux(),
            vault(),
            &[mine.clone()],
            now(),
        );
        assert_eq!(plan.counts().archived_duplicates, 1);
        // The older vault item stays and answers for the 1Password item.
        let kept = plan.items.iter().find(|p| p.item.id == mine.id).unwrap();
        assert!(
            kept.item
                .tags
                .iter()
                .any(|t| t == "onepass:src:1pux:vault-perso/google-acct")
        );
        assert!(plan.items.iter().all(|p| p.item.title != "Google"));
        let gone = &plan.archived_duplicates[0];
        assert!(gone.archived);
        assert_eq!(gone.title, "Google");
        assert!(gone.tags.iter().all(|t| !is_source_tag(t)));
        // Imported again: nothing new, nothing folded twice.
        let vault_now = written(&plan);
        let again = reconcile(Format::OnePasswordPux, pux(), vault(), &vault_now, now());
        assert_eq!(again.counts().added, 0);
        assert_eq!(again.counts().archived_duplicates, 0);
    }

    #[test]
    fn near_duplicates_are_left_alone() {
        let first = written(&reconcile(
            Format::OnePasswordPux,
            pux(),
            vault(),
            &[],
            now(),
        ));
        let mut other = first.iter().find(|e| e.title == "Google").unwrap().clone();
        other.id = Id::new();
        other.title = "Gmail".into();
        other.tags.clear();
        other.field_mut("password").unwrap().value =
            FieldValue::Password(zeroize::Zeroizing::new("Another-Password".into()));
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &[other], now());
        assert_eq!(plan.counts().archived_duplicates, 0);
    }
}
