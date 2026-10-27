//! Metadata tools (`metadata` scope): vaults, item cards and search. They
//! never return a value, the notes or the computed subtitle.

use super::{Call, CallResult, McpTools, Refusal, kind_name, pick, untrusted};
use crate::policy::Scope;
use crate::port::{VaultInfo, VaultPort};
use onepass_core::model::{FieldValue, Item};
use serde_json::{Map, Value, json};

/// Most results `search_items` returns.
pub(crate) const SEARCH_LIMIT: usize = 50;

/// Whether a field holds something, without exposing what.
fn filled(v: &FieldValue) -> bool {
    match v {
        FieldValue::Empty => false,
        FieldValue::Text(s)
        | FieldValue::Url(s)
        | FieldValue::Email(s)
        | FieldValue::Phone(s)
        | FieldValue::Menu(s) => !s.trim().is_empty(),
        FieldValue::Concealed(s)
        | FieldValue::Password(s)
        | FieldValue::Otp(s)
        | FieldValue::Mnemonic(s) => !s.is_empty(),
        _ => true,
    }
}

/// The metadata card of an item: no value, no notes, no subtitle.
pub(crate) fn item_card(v: &VaultInfo, item: &Item) -> Value {
    let urls: Vec<Value> = item
        .urls
        .iter()
        .map(|u| json!({"label": u.label, "url": u.url}))
        .collect();
    let fields: Vec<Value> = item
        .sections
        .iter()
        .flat_map(|s| {
            s.fields.iter().map(move |f| {
                json!({
                    "section": s.id,
                    "id": f.id,
                    "label": f.label,
                    "kind": kind_name(&f.kind),
                    "filled": filled(&f.value),
                })
            })
        })
        .collect();
    json!({
        "id": item.id.to_string(),
        "vault_id": v.id.to_string(),
        "vault": v.name,
        "title": item.title,
        "type": kind_name(&item.item_type),
        "tags": item.tags,
        "urls": urls,
        "archived": item.archived,
        "fields": fields,
    })
}

/// Sorts by title (ignoring case), then id, and renders the cards.
fn cards(mut found: Vec<(VaultInfo, Item)>, limit: usize) -> Value {
    found.sort_by(|(_, a), (_, b)| {
        a.title
            .to_lowercase()
            .cmp(&b.title.to_lowercase())
            .then(a.id.cmp(&b.id))
    });
    Value::Array(
        found
            .iter()
            .take(limit)
            .map(|(v, i)| item_card(v, i))
            .collect(),
    )
}

fn arg_str<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

impl<P: VaultPort> McpTools<P> {
    /// The vaults a metadata call covers: the one named (visible, with the
    /// metadata scope), else every visible vault with that scope.
    fn metadata_targets(
        &mut self,
        key: Option<&str>,
        call: &mut Call,
    ) -> Result<Vec<VaultInfo>, Refusal> {
        match key {
            Some(key) => {
                let v = self.find_vault(key)?;
                call.vault_id = Some(v.id);
                self.require(&v, Scope::Metadata)?;
                Ok(vec![v])
            }
            None => Ok(self
                .visible_vaults()?
                .into_iter()
                .filter(|v| self.scopes(v).contains(&Scope::Metadata))
                .collect()),
        }
    }

    /// Live items of `vaults` that pass `keep`.
    fn collect(
        &mut self,
        vaults: Vec<VaultInfo>,
        keep: impl Fn(&Item) -> bool,
    ) -> Result<Vec<(VaultInfo, Item)>, Refusal> {
        let mut found = Vec::new();
        for v in vaults {
            for item in self.live_items(v.id)? {
                if keep(&item) {
                    found.push((v.clone(), item));
                }
            }
        }
        Ok(found)
    }

    /// `list_vaults {}`: visible vaults with the metadata scope.
    pub(super) fn list_vaults(&mut self) -> CallResult {
        let mut vaults: Vec<(VaultInfo, Vec<&'static str>)> = self
            .visible_vaults()?
            .into_iter()
            .filter_map(|v| {
                let scopes = self.scopes(&v);
                scopes
                    .contains(&Scope::Metadata)
                    .then(|| (v, scopes.iter().map(|s| s.as_str()).collect()))
            })
            .collect();
        vaults.sort_by(|(a, _), (b, _)| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        let out: Vec<Value> = vaults
            .into_iter()
            .map(|(v, scopes)| json!({"id": v.id.to_string(), "name": v.name, "scopes": scopes}))
            .collect();
        Ok(untrusted(Value::Array(out)))
    }

    /// `list_items {vault?, type?, tag?, include_archived?}`.
    pub(super) fn list_items(&mut self, args: &Map<String, Value>, call: &mut Call) -> CallResult {
        let vaults = self.metadata_targets(arg_str(args, "vault"), call)?;
        let item_type = arg_str(args, "type");
        let tag = arg_str(args, "tag").map(str::to_lowercase);
        let include_archived = args
            .get("include_archived")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let found = self.collect(vaults, |i| {
            (include_archived || !i.archived)
                && item_type.is_none_or(|t| kind_name(&i.item_type) == t)
                && tag
                    .as_ref()
                    .is_none_or(|t| i.tags.iter().any(|g| g.to_lowercase() == *t))
        })?;
        Ok(untrusted(cards(found, usize::MAX)))
    }

    /// `search_items {query, vault?}`: substring of title, URL or tag,
    /// ignoring case; archived items included; at most [`SEARCH_LIMIT`].
    pub(super) fn search_items(
        &mut self,
        args: &Map<String, Value>,
        call: &mut Call,
    ) -> CallResult {
        let vaults = self.metadata_targets(arg_str(args, "vault"), call)?;
        let query = arg_str(args, "query").unwrap_or_default().to_lowercase();
        let found = self.collect(vaults, |i| {
            i.title.to_lowercase().contains(&query)
                || i.urls.iter().any(|u| u.url.to_lowercase().contains(&query))
                || i.tags.iter().any(|t| t.to_lowercase().contains(&query))
        })?;
        Ok(untrusted(cards(found, SEARCH_LIMIT)))
    }

    /// `get_item {item, vault?}`: one card. Without `vault`, the item is
    /// looked up only in the visible vaults that grant `metadata`: a title
    /// held by a vault without that scope is neither found nor ambiguous.
    pub(super) fn get_item(&mut self, args: &Map<String, Value>, call: &mut Call) -> CallResult {
        let key = arg_str(args, "item").unwrap_or_default();
        let ambiguous = "ambiguous item, use its id";
        let (vault, item) = match arg_str(args, "vault") {
            Some(vkey) => {
                let v = self.find_vault(vkey)?;
                call.vault_id = Some(v.id);
                self.require(&v, Scope::Metadata)?;
                let items = self.live_items(v.id)?;
                let item = pick(&items, key, ambiguous, |i| i.id, |i| &i.title)?.clone();
                (v, item)
            }
            None => {
                let vaults = self.metadata_targets(None, call)?;
                let all = self.collect(vaults, |_| true)?;
                let (v, item) = pick(&all, key, ambiguous, |(_, i)| i.id, |(_, i)| &i.title)?;
                call.vault_id = Some(v.id);
                (v.clone(), item.clone())
            }
        };
        call.item_id = Some(item.id);
        Ok(untrusted(item_card(&vault, &item)))
    }
}
