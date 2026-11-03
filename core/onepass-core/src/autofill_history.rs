//! Autofill history: which login the user chose on which site, from which
//! browser and browser profile, on this device. The ranking learns from it
//! (`fill_plan::learned`) which account to offer first.
//!
//! Privacy: an event never holds a password, a username or any field
//! value. It names an item by its id, a site by its registrable domain, a
//! browser profile by an opaque id the extension draws and keeps in its own
//! storage (and its display name only when the browser gives one). The
//! events live in the device's own database, each sealed under a key
//! derived from the account keyset (`BlobKind::AutofillHistory`), and filed
//! under a keyed tag of the site, so the file shows neither the sites nor
//! the items. They are device-local: never synced, never sent anywhere.
//! A switch turns the history off (and erases it), "clear" erases it, a
//! forgotten site loses its events, and the Travel Mode erases it.
//!
//! Wire format: `AutofillEvent` is postcard behind a version byte. Postcard
//! encodes enum variants by index: new variants of `BrowserKind`,
//! `AutofillAction` and `EventSource` are only ever appended. A row a build
//! cannot open (another version, an older keyset after a rotation) is
//! dropped at the next read: the history is a hint, never a lockout.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::crypto::aead::{Aad, BlobKind, open, seal};
use crate::crypto::key::SymmetricKey;
use crate::id::Id;
use crate::{Error, Result, ValidationError};

/// Events kept per site, the oldest dropped first.
pub const MAX_PER_SITE: usize = 200;
/// Events kept on the device, the oldest dropped first.
pub const MAX_TOTAL: usize = 5000;
/// An event older than this is dropped.
pub const RETENTION_DAYS: i64 = 180;
/// Longest opaque profile id the extension may send.
pub const MAX_PROFILE_ID: usize = 64;
/// Longest profile display name kept.
pub const MAX_PROFILE_NAME: usize = 64;
/// Most item ids a `Shown` event lists.
pub const MAX_SHOWN: usize = 8;
/// Longest site kept (a DNS name).
pub const MAX_SITE: usize = 253;

/// Version byte in front of an encoded event.
const EVENT_VERSION: u8 = 1;
/// Schema of the AAD of a sealed event.
const AAD_SCHEMA: u16 = 1;
const KEY_SALT: &[u8] = b"onepass/autofill-history/v1";
const SEAL_INFO: &[u8] = b"seal";
const TAG_INFO: &[u8] = b"site-tag";

/// The browser an event came from. `SystemAutoFill`: the iOS or macOS
/// AutoFill (the credential provider), which never learns the calling app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserKind {
    Unknown,
    Safari,
    Chrome,
    Edge,
    Brave,
    Firefox,
    Arc,
    Opera,
    Vivaldi,
    Chromium,
    SystemAutoFill,
}

/// What the user did with the suggestions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutofillAction {
    /// A list of suggestions was shown (`shown` holds it, best first).
    Shown,
    /// The user chose `item_id` at `rank` of the list shown.
    Picked,
    /// `item_id` was written into the page.
    Filled,
    /// The fill of `item_id` worked: the page moved on, a chain ended, or
    /// a save confirmed it.
    Submitted,
    /// The list closed without a choice; `item_id` was its first entry.
    Dismissed,
    /// `item_id` was offered first and the user chose another one.
    PickedOther,
}

/// Which surface recorded the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Extension,
    SystemAutoFill,
    App,
}

/// The browser and browser profile a choice was made in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientContext {
    pub browser: BrowserKind,
    /// Opaque id the extension drew for its browser profile.
    pub profile_id: Option<String>,
    /// The profile's display name, when the browser exposes one.
    pub profile_name: Option<String>,
}

impl ClientContext {
    /// No browser and no profile known.
    pub fn unknown() -> ClientContext {
        ClientContext {
            browser: BrowserKind::Unknown,
            profile_id: None,
            profile_name: None,
        }
    }

    /// The system AutoFill: no browser profile.
    pub fn system_autofill() -> ClientContext {
        ClientContext {
            browser: BrowserKind::SystemAutoFill,
            profile_id: None,
            profile_name: None,
        }
    }

    /// Same browser and same profile id (the name is display only).
    pub fn same_context(&self, other: &ClientContext) -> bool {
        self.browser == other.browser && self.profile_id == other.profile_id
    }

    /// Checked: a profile id of at most `MAX_PROFILE_ID` characters among
    /// `A-Z a-z 0-9 - _`, a name of at most `MAX_PROFILE_NAME` characters
    /// without a control character. An empty id or name is none.
    pub fn validated(self) -> Result<ClientContext> {
        let profile_id = match self.profile_id.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(s)
                if s.len() <= MAX_PROFILE_ID
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
            {
                Some(s.to_owned())
            }
            Some(_) => return Err(invalid("profile_id", "not an opaque profile id")),
        };
        let profile_name = match self.profile_name.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(s)
                if s.chars().count() <= MAX_PROFILE_NAME && !s.chars().any(char::is_control) =>
            {
                Some(s.to_owned())
            }
            Some(_) => return Err(invalid("profile_name", "not a profile name")),
        };
        Ok(ClientContext {
            browser: self.browser,
            profile_id,
            profile_name,
        })
    }
}

/// One choice, or one list shown. Never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofillEvent {
    pub at: OffsetDateTime,
    pub action: AutofillAction,
    pub source: EventSource,
    /// Registrable domain (eTLD+1), lower case.
    pub site: String,
    pub item_id: Option<Id>,
    /// Position of `item_id` in the list shown, 0 first, when known.
    pub rank: Option<u8>,
    /// `Shown`: the items listed, best first, at most `MAX_SHOWN`.
    pub shown: Vec<Id>,
    pub client: ClientContext,
    /// This device's id in the device list, once registered.
    pub device_id: Option<Id>,
}

impl AutofillEvent {
    /// Checked as a caller's input: a site, an item for every action but
    /// `Shown`, at most `MAX_SHOWN` shown items, a valid client.
    pub fn validated(mut self) -> Result<AutofillEvent> {
        let site = self.site.trim().to_ascii_lowercase();
        if site.is_empty() || site.len() > MAX_SITE || site.contains(['/', ':', ' ']) {
            return Err(invalid("site", "not a registrable domain"));
        }
        self.site = site;
        if self.action != AutofillAction::Shown && self.item_id.is_none() {
            return Err(invalid("item_id", "missing"));
        }
        if self.shown.len() > MAX_SHOWN {
            return Err(invalid("shown", "too many items"));
        }
        self.client = self.client.validated()?;
        Ok(self)
    }

    /// A positive choice of `item_id`: picked, filled or submitted.
    pub fn is_choice(&self) -> bool {
        matches!(
            self.action,
            AutofillAction::Picked | AutofillAction::Filled | AutofillAction::Submitted
        )
    }
}

fn invalid(field: &str, reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: field.into(),
        reason,
    })
}

/// The keys of the history of one account: sealing, and the keyed site
/// tag. Derived from the account's KEM secret, so a key rotation leaves
/// the old rows unreadable (they are dropped at the next read).
pub struct HistoryKeys {
    seal: SymmetricKey,
    tag: SymmetricKey,
}

impl HistoryKeys {
    /// HKDF-SHA256 of `ikm` (the account's secret key material) salted
    /// with the history label, bound to the account id.
    pub(crate) fn derive(ikm: &[u8], account_id: Id) -> Result<HistoryKeys> {
        let root = crate::crypto::key::hkdf32(KEY_SALT, ikm, &[&account_id.0])?;
        Ok(HistoryKeys {
            seal: root.derive(SEAL_INFO)?,
            tag: root.derive(TAG_INFO)?,
        })
    }

    /// HMAC-SHA256 of the site under the tag key: what the store files
    /// the events of a site under, without the site in clear.
    pub fn site_tag(&self, site: &str) -> [u8; 32] {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, self.tag.expose());
        let t = aws_lc_rs::hmac::sign(&key, site.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(t.as_ref());
        out
    }

    fn aad(tag: &[u8; 32]) -> Aad {
        let mut id = [0u8; 16];
        id.copy_from_slice(&tag[..16]);
        Aad {
            blob_id: Id(id),
            vault_id: None,
            schema: AAD_SCHEMA,
        }
    }

    /// The sealed row of `ev`, bound to its site tag (a row moved under
    /// another site's tag does not open).
    pub fn seal_event(&self, tag: &[u8; 32], ev: &AutofillEvent) -> Result<Vec<u8>> {
        let mut plain = vec![EVENT_VERSION];
        plain
            .extend(postcard::to_allocvec(ev).map_err(|_| Error::InvalidFormat("autofill event"))?);
        seal(
            &self.seal,
            BlobKind::AutofillHistory,
            &Self::aad(tag),
            &plain,
        )
    }

    /// The event of a sealed row filed under `tag`.
    pub fn open_event(&self, tag: &[u8; 32], blob: &[u8]) -> Result<AutofillEvent> {
        let plain = open(&self.seal, BlobKind::AutofillHistory, &Self::aad(tag), blob)?;
        match plain.split_first() {
            Some((&EVENT_VERSION, body)) => {
                postcard::from_bytes(body).map_err(|_| Error::InvalidFormat("autofill event"))
            }
            _ => Err(Error::InvalidFormat("autofill event version")),
        }
    }
}

/// Is `ev` past the retention at `now`?
pub fn expired(ev: &AutofillEvent, now: OffsetDateTime) -> bool {
    now - ev.at > time::Duration::days(RETENTION_DAYS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> HistoryKeys {
        HistoryKeys::derive(&[7u8; 64], Id([1; 16])).unwrap()
    }

    fn ev(action: AutofillAction) -> AutofillEvent {
        AutofillEvent {
            at: OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            action,
            source: EventSource::Extension,
            site: "Example.com".into(),
            item_id: Some(Id([2; 16])),
            rank: Some(1),
            shown: vec![],
            client: ClientContext {
                browser: BrowserKind::Chrome,
                profile_id: Some("p-1".into()),
                profile_name: Some("Work".into()),
            },
            device_id: None,
        }
    }

    #[test]
    fn seal_round_trip_bound_to_its_site() {
        let k = keys();
        let e = ev(AutofillAction::Picked).validated().unwrap();
        assert_eq!(e.site, "example.com");
        let tag = k.site_tag(&e.site);
        let blob = k.seal_event(&tag, &e).unwrap();
        assert_eq!(k.open_event(&tag, &blob).unwrap(), e);
        // Moved under another site: refused.
        let other = k.site_tag("other.com");
        assert!(k.open_event(&other, &blob).is_err());
        // Another account: refused.
        let k2 = HistoryKeys::derive(&[7u8; 64], Id([9; 16])).unwrap();
        assert!(k2.open_event(&tag, &blob).is_err());
        assert_ne!(k2.site_tag("example.com"), tag);
    }

    #[test]
    fn sealed_row_holds_no_site_or_profile_in_clear() {
        let k = keys();
        let e = ev(AutofillAction::Picked).validated().unwrap();
        let tag = k.site_tag(&e.site);
        let blob = k.seal_event(&tag, &e).unwrap();
        let hay = String::from_utf8_lossy(&blob);
        assert!(!hay.contains("example"));
        assert!(!hay.contains("Work"));
        assert!(!hay.contains("p-1"));
    }

    #[test]
    fn validation() {
        let mut e = ev(AutofillAction::Picked);
        e.item_id = None;
        assert!(e.validated().is_err());
        let mut e = ev(AutofillAction::Shown);
        e.item_id = None;
        e.shown = vec![Id([3; 16]); MAX_SHOWN + 1];
        assert!(e.clone().validated().is_err());
        e.shown.truncate(MAX_SHOWN);
        assert!(e.validated().is_ok());
        let mut e = ev(AutofillAction::Picked);
        e.client.profile_id = Some("has space".into());
        assert!(e.validated().is_err());
        let mut e = ev(AutofillAction::Picked);
        e.client.profile_name = Some("bad\nname".into());
        assert!(e.validated().is_err());
        let mut e = ev(AutofillAction::Picked);
        e.site = "https://x.com/".into();
        assert!(e.validated().is_err());
        let mut e = ev(AutofillAction::Picked);
        e.client.profile_id = Some("  ".into());
        assert_eq!(e.validated().unwrap().client.profile_id, None);
    }

    /// Postcard indices of the enums: appended only.
    #[test]
    fn wire_indices_pinned() {
        let b = |v: BrowserKind| postcard::to_allocvec(&v).unwrap()[0];
        assert_eq!(b(BrowserKind::Unknown), 0);
        assert_eq!(b(BrowserKind::Safari), 1);
        assert_eq!(b(BrowserKind::Chrome), 2);
        assert_eq!(b(BrowserKind::SystemAutoFill), 10);
        let a = |v: AutofillAction| postcard::to_allocvec(&v).unwrap()[0];
        assert_eq!(a(AutofillAction::Shown), 0);
        assert_eq!(a(AutofillAction::PickedOther), 5);
        let s = |v: EventSource| postcard::to_allocvec(&v).unwrap()[0];
        assert_eq!(s(EventSource::Extension), 0);
        assert_eq!(s(EventSource::App), 2);
    }

    #[test]
    fn retention() {
        let e = ev(AutofillAction::Picked);
        assert!(!expired(&e, e.at + time::Duration::days(RETENTION_DAYS)));
        assert!(expired(&e, e.at + time::Duration::days(RETENTION_DAYS + 1)));
    }
}
