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

use std::collections::{HashMap, HashSet};

use super::{Format, Import, is_source_tag};
use crate::id::Id;
use crate::model::{FieldValue, Item, ItemType, LoginMethod, PasswordHistoryEntry};
use crate::watchtower::host::host_of;

/// What a re-import does with one imported item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// New in the vault.
    Added,
    /// Updates a vault item: a fallback converted, or something added.
    Fixed,
    /// The vault item already holds everything: nothing is written.
    Unchanged,
}

/// One imported item ready for the vault, and what it does there.
#[derive(Debug, Clone)]
pub struct Planned {
    pub item: Item,
    pub outcome: Outcome,
}

const IMPORTED_SECTION: &str = "imported";

/// The items of `import` ready for `vault`, matched against `existing` (the
/// vault's items). New items get a new id; matched ones the id of their
/// vault item. The source folder is kept as a tag and "sign in with"
/// methods point at the final id of their account item.
pub fn reconcile(format: Format, import: Import, vault: Id, existing: &[Item]) -> Vec<Planned> {
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
                merge(e, item)
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
    out
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
    match (source_tag(e), source_tag(item)) {
        (Some(a), Some(b)) => source_kind(a) == source_kind(b) && a != b,
        _ => false,
    }
}

fn compatible_type(e: &Item, item: &Item) -> bool {
    e.item_type == item.item_type
        || e.item_type == ItemType::SecureNote
        || (e.item_type == ItemType::Password && item.item_type == ItemType::Login)
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
            outcome: Outcome::Fixed,
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

/// Counts of a plan: (added, fixed, unchanged).
pub fn counts(plan: &[Planned]) -> (u32, u32, u32) {
    let n = |o: Outcome| {
        u32::try_from(plan.iter().filter(|p| p.outcome == o).count()).unwrap_or(u32::MAX)
    };
    (n(Outcome::Added), n(Outcome::Fixed), n(Outcome::Unchanged))
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

    fn by<'a>(plan: &'a [Planned], title: &str) -> &'a Planned {
        plan.iter().find(|p| p.item.title == title).unwrap()
    }

    fn written(plan: &[Planned]) -> Vec<Item> {
        plan.iter().map(|p| p.item.clone()).collect()
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
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &existing);
        assert_eq!(plan.len(), existing.len());
        // Every source item found its vault item: nothing added.
        assert_eq!(counts(&plan).0, 0, "no duplicate");
        let ids: HashSet<Id> = existing.iter().map(|e| e.id).collect();
        assert!(plan.iter().all(|p| ids.contains(&p.item.id)));
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
            assert_eq!(p.outcome, Outcome::Fixed, "{title}");
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
    }

    #[test]
    fn importing_again_changes_nothing() {
        let first = reconcile(Format::OnePasswordPux, pux(), vault(), &legacy_vault());
        let vault_now = written(&first);
        let again = reconcile(Format::OnePasswordPux, pux(), vault(), &vault_now);
        assert_eq!(
            counts(&again),
            (0, 0, u32::try_from(vault_now.len()).unwrap())
        );
        for (a, b) in again.iter().zip(&vault_now) {
            assert_eq!(a.item.id, b.id);
        }
    }

    #[test]
    fn fresh_vault_adds_everything() {
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &[]);
        let n = u32::try_from(plan.len()).unwrap();
        assert_eq!(counts(&plan), (n, 0, 0));
        assert!(plan.iter().all(|p| p.item.vault_id == vault()));
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
        let vault_now = written(&reconcile(Format::OnePasswordPux, pux(), vault(), &[]));
        let plan = reconcile(Format::CredentialExchange, cxf(), vault(), &vault_now);
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
        let demo = plan.iter().find(|p| p.item.id == demo_id).unwrap();
        let keys = passkeys(&demo.item);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].rp_id, "webauthn.example.com");
        assert_eq!(keys[0].credential_id, vec![1, 2, 3, 4]);
        assert_eq!(keys[0].user_handle, b"user1".to_vec());
        assert_eq!(keys[0].private_key.as_slice(), b"keyblo");
        assert!(demo.item.login_methods.contains(&LoginMethod::Passkey));
        validate(&demo.item).unwrap();
        // Matched by site and account, whatever the title ("GitHub" here).
        let dev = plan.iter().find(|p| p.item.id == dev_id).unwrap();
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
                plan.iter()
                    .find(|p| p.item.id == e.id)
                    .map_or_else(|| e.clone(), |p| p.item.clone())
            })
            .collect();
        let again = reconcile(Format::CredentialExchange, cxf(), vault(), &vault_after);
        assert_eq!(counts(&again), (0, 0, 2));
    }

    #[test]
    fn a_value_changed_in_the_vault_after_the_export_wins() {
        let mut vault_now = written(&reconcile(Format::OnePasswordPux, pux(), vault(), &[]));
        let google = vault_now.iter_mut().find(|e| e.title == "Google").unwrap();
        google.field_mut("password").unwrap().value =
            FieldValue::Password(zeroize::Zeroizing::new("Changed-In-OnePass".into()));
        google.updated_at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &vault_now);
        let g = by(&plan, "Google");
        assert_eq!(g.outcome, Outcome::Unchanged);
        assert!(matches!(
            &g.item.field("password").unwrap().value,
            FieldValue::Password(p) if p.as_str() == "Changed-In-OnePass"
        ));
    }

    #[test]
    fn a_value_changed_in_the_source_later_wins_and_keeps_history() {
        let mut vault_now = written(&reconcile(Format::OnePasswordPux, pux(), vault(), &[]));
        let google = vault_now.iter_mut().find(|e| e.title == "Google").unwrap();
        google.field_mut("password").unwrap().value =
            FieldValue::Password(zeroize::Zeroizing::new("Older-Password".into()));
        google.updated_at = OffsetDateTime::from_unix_timestamp(1_500_000_000).unwrap();
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &vault_now);
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
        let plan = reconcile(Format::OnePasswordPux, pux(), vault(), &[note.clone()]);
        let notion = by(&plan, "Notion");
        assert_eq!(notion.outcome, Outcome::Added);
        assert_ne!(notion.item.id, note.id);
    }

    #[test]
    fn other_formats_always_add() {
        let existing = written(&reconcile(Format::OnePasswordPux, pux(), vault(), &[]));
        let mut csv = pux();
        for it in &mut csv.items {
            it.item.tags.retain(|t| !is_source_tag(t));
        }
        let plan = reconcile(Format::ChromeCsv, csv, vault(), &existing);
        assert_eq!(counts(&plan).1 + counts(&plan).2, 0);
    }
}
