//! Timeline of an item for the detail footer: kinds, times and labels,
//! never a value (see `onepass_core::model::events`).

use onepass_core::model::events::{self, EventKind, TimelineKind};

use crate::convert::{parse_id, ts};
use crate::error::OnePassError;
use crate::session::{Session, find_item, find_vault};

/// One row of an item's timeline.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTimelineEvent {
    /// `created`, `imported`, `field_added`, `field_removed`,
    /// `field_changed`, `password_changed`, `title_changed`,
    /// `website_added`, `website_removed`, `moved`, `favorited`,
    /// `unfavorited`, `archived`, `unarchived`, `trashed`, `restored`,
    /// `passkey_added`, `passkey_removed`, `attachment_added`, `modified`.
    pub kind: String,
    /// Unix seconds.
    pub at: i64,
    /// Field label, website host, target vault name, import format, passkey
    /// relying party or attachment name; empty for the others.
    pub detail: String,
}

fn row(kind: &TimelineKind) -> (&'static str, String) {
    let k = match kind {
        TimelineKind::Modified => return ("modified", String::new()),
        TimelineKind::Event(k) => k,
    };
    match k {
        EventKind::Created => ("created", String::new()),
        EventKind::FieldAdded { label } => ("field_added", label.clone()),
        EventKind::FieldRemoved { label } => ("field_removed", label.clone()),
        EventKind::FieldChanged { label } => ("field_changed", label.clone()),
        EventKind::PasswordChanged => ("password_changed", String::new()),
        EventKind::TitleChanged => ("title_changed", String::new()),
        EventKind::WebsiteAdded { host } => ("website_added", host.clone()),
        EventKind::WebsiteRemoved { host } => ("website_removed", host.clone()),
        EventKind::Moved { to, .. } => ("moved", to.clone()),
        EventKind::Favorited => ("favorited", String::new()),
        EventKind::Unfavorited => ("unfavorited", String::new()),
        EventKind::Archived => ("archived", String::new()),
        EventKind::Unarchived => ("unarchived", String::new()),
        EventKind::Trashed => ("trashed", String::new()),
        EventKind::Restored => ("restored", String::new()),
        EventKind::Imported { format } => ("imported", format.clone()),
        EventKind::PasskeyAdded { rp_id } => ("passkey_added", rp_id.clone()),
        EventKind::PasskeyRemoved { rp_id } => ("passkey_removed", rp_id.clone()),
        EventKind::AttachmentAdded { name } => ("attachment_added", name.clone()),
    }
}

#[uniffi::export]
impl Session {
    /// The item's timeline, newest first. Items saved before events existed
    /// get a synthesized one (creation, previous passwords, last change).
    pub fn item_timeline(
        &self,
        vault_id: String,
        item_id: String,
    ) -> Result<Vec<FfiTimelineEvent>, OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            let item = find_item(repo, &vault, item_id)?;
            Ok(events::timeline(&item)
                .iter()
                .map(|e| {
                    let (kind, detail) = row(&e.kind);
                    FfiTimelineEvent {
                        kind: kind.to_owned(),
                        at: ts(e.at),
                        detail,
                    }
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    fn set(item: &mut FfiItem, id: &str, value: &str) {
        for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            if f.id == id {
                f.value = if id == "password" {
                    FfiFieldValue::Password {
                        value: value.into(),
                    }
                } else {
                    FfiFieldValue::Text {
                        value: value.into(),
                    }
                };
            }
        }
    }

    #[test]
    fn timeline_follows_the_item_and_never_holds_a_value() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("t.db").to_string_lossy().into_owned();
        let fast = FfiKdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        };
        let s = create_account_with_kdf(path, "pw".into(), fast)
            .unwrap()
            .session;
        let home = s.vaults().unwrap()[0].id.clone();
        let atlas = s
            .create_vault(FfiVaultMeta {
                name: "Projet Atlas".into(),
                icon: "folder".into(),
                color: "#336699".into(),
                travel_safe: true,
                mcp_access: false,
            })
            .unwrap()
            .id;
        let mut item = s
            .new_item(home.clone(), FfiItemType::Login, "GitHub".into())
            .unwrap();
        set(&mut item, "username", "camille");
        set(&mut item, "password", "first-secret-1");
        let mut item = s.save_item(item).unwrap();
        set(&mut item, "password", "second-secret-2");
        let item = s.save_item(item).unwrap();
        s.set_favorite(home.clone(), item.id.clone(), true).unwrap();
        s.archive_item(home.clone(), item.id.clone()).unwrap();
        s.move_item(item.id.clone(), home.clone(), atlas.clone())
            .unwrap();
        s.trash_item(atlas.clone(), item.id.clone()).unwrap();
        s.restore_item(atlas.clone(), item.id.clone()).unwrap();

        let t = s.item_timeline(atlas, item.id).unwrap();
        let kinds: Vec<&str> = t.iter().map(|e| e.kind.as_str()).collect();
        for k in [
            "created",
            "password_changed",
            "favorited",
            "archived",
            "moved",
            "trashed",
            "restored",
        ] {
            assert!(kinds.contains(&k), "{k} in {kinds:?}");
        }
        assert!(t.windows(2).all(|w| w[0].at >= w[1].at), "newest first");
        assert_eq!(t.last().unwrap().kind, "created");
        let moved = t.iter().find(|e| e.kind == "moved").unwrap();
        assert_eq!(moved.detail, "Projet Atlas");
        let dump = format!("{t:?}");
        assert!(!dump.contains("secret") && !dump.contains("camille"));
    }
}
