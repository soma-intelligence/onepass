//! `onepass item ...` and the helpers other commands share to find items.
//!
//! Field input is `--field id=value`. The value is read according to the
//! kind of the template field it targets. Kinds with a structured value
//! (File, Passkey, SshKey, Location, Address, Barcode, ItemLink, Money)
//! cannot be typed on a command line and are refused for now. If an item has
//! several fields with the same id (repeatable ones), the first is set.

use clap::Subcommand;
use onepass_core::Id;
use onepass_core::model::{FieldType, FieldValue, Item, ItemType, new_item};
use onepass_core::repo::Repository;
use onepass_core::store::SqliteStore;
use onepass_core::vault::Vault;
use serde_json::{Value, json};
use time::{Date, Month, OffsetDateTime};
use zeroize::Zeroizing;

use super::vault::{all, find_vault};
use crate::session::{CliError, Ctx, stored, with_session};

const MASK: &str = "••••••••";

#[derive(Subcommand)]
pub enum ItemCmd {
    /// List the items (the trash is left out).
    List {
        #[arg(long)]
        vault: Option<String>,
        #[arg(long = "type", value_parser = parse_type)]
        item_type: Option<ItemType>,
    },
    /// Show an item; secret fields are masked unless --reveal.
    Get {
        /// Item id or title.
        key: String,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        reveal: bool,
    },
    /// Create an item.
    Create {
        /// Item type in kebab-case (login, credit-card, id-card, ...).
        #[arg(value_parser = parse_type)]
        item_type: ItemType,
        #[arg(long)]
        title: String,
        /// `id=value`, repeatable.
        #[arg(long = "field")]
        fields: Vec<String>,
        /// Target vault (default: Personnel, or the only vault).
        #[arg(long)]
        vault: Option<String>,
    },
    /// Change fields of an item.
    Edit {
        key: String,
        /// `id=value`, repeatable.
        #[arg(long = "field", required = true)]
        fields: Vec<String>,
        #[arg(long)]
        vault: Option<String>,
    },
    /// Move an item to the trash.
    Delete {
        key: String,
        #[arg(long)]
        vault: Option<String>,
    },
    /// Move an item to another vault.
    Move {
        key: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        vault: Option<String>,
    },
}

/// `ItemType` as its kebab-case command line name.
fn type_name(t: ItemType) -> String {
    let mut out = String::new();
    for (i, c) in format!("{t:?}").chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                out.push('-');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_type(s: &str) -> Result<ItemType, String> {
    ItemType::ALL
        .into_iter()
        .find(|t| type_name(*t) == s.to_lowercase())
        .ok_or_else(|| {
            let names: Vec<String> = ItemType::ALL.into_iter().map(type_name).collect();
            format!(
                "unknown item type '{s}', expected one of: {}",
                names.join(", ")
            )
        })
}

pub fn run(ctx: &Ctx, cmd: ItemCmd) -> Result<(), CliError> {
    with_session(ctx, |repo| match cmd {
        ItemCmd::List { vault, item_type } => list(ctx, repo, vault.as_deref(), item_type),
        ItemCmd::Get { key, vault, reveal } => get(ctx, repo, &key, vault.as_deref(), reveal),
        ItemCmd::Create {
            item_type,
            title,
            fields,
            vault,
        } => create(ctx, repo, item_type, &title, &fields, vault.as_deref()),
        ItemCmd::Edit { key, fields, vault } => edit(repo, &key, &fields, vault.as_deref()),
        ItemCmd::Delete { key, vault } => {
            let vaults = all(repo)?;
            let (vi, item) = find_item(repo, &vaults, vault.as_deref(), &key)?;
            stored(repo.trash_item(&vaults[vi], item.id))?;
            Ok(())
        }
        ItemCmd::Move { key, to, vault } => {
            let vaults = all(repo)?;
            let (vi, item) = find_item(repo, &vaults, vault.as_deref(), &key)?;
            let ti = find_vault(&vaults, &to)?;
            stored(repo.move_item(item.id, &vaults[vi], &vaults[ti]))?;
            Ok(())
        }
    })
}

/// The live (not trashed) item whose id, or else whose title (ignoring
/// case), is `key`, in the given vault or in all of them. Returns the index
/// of its vault in `vaults`. Several titles matching is a usage error.
pub fn find_item(
    repo: &mut Repository<SqliteStore>,
    vaults: &[Vault],
    vault: Option<&str>,
    key: &str,
) -> Result<(usize, Item), CliError> {
    let indexes: Vec<usize> = match vault {
        Some(v) => vec![find_vault(vaults, v)?],
        None => (0..vaults.len()).collect(),
    };
    let mut live: Vec<(usize, Item)> = Vec::new();
    for vi in indexes {
        for item in stored(repo.items(&vaults[vi]))? {
            if item.trashed_at.is_none() {
                live.push((vi, item));
            }
        }
    }
    if let Ok(id) = key.parse::<Id>()
        && let Some(pos) = live.iter().position(|(_, i)| i.id == id)
    {
        return Ok(live.swap_remove(pos));
    }
    let wanted = key.to_lowercase();
    let mut hits: Vec<usize> = live
        .iter()
        .enumerate()
        .filter(|(_, (_, i))| i.title.to_lowercase() == wanted)
        .map(|(n, _)| n)
        .collect();
    match hits.len() {
        0 => Err(CliError::not_found(format!("no item matches '{key}'"))),
        1 => Ok(live.swap_remove(hits.remove(0))),
        n => Err(CliError::usage(format!(
            "ambiguous: {n} items are titled '{key}', use the item id"
        ))),
    }
}

fn list(
    ctx: &Ctx,
    repo: &mut Repository<SqliteStore>,
    vault: Option<&str>,
    item_type: Option<ItemType>,
) -> Result<(), CliError> {
    let vaults = all(repo)?;
    let indexes: Vec<usize> = match vault {
        Some(v) => vec![find_vault(&vaults, v)?],
        None => (0..vaults.len()).collect(),
    };
    let mut rows: Vec<(String, String, String, String)> = Vec::new();
    for vi in indexes {
        for item in stored(repo.items(&vaults[vi]))? {
            if item.trashed_at.is_some() || item_type.is_some_and(|t| t != item.item_type) {
                continue;
            }
            rows.push((
                item.id.to_string(),
                type_name(item.item_type),
                vaults[vi].meta.name.clone(),
                item.title,
            ));
        }
    }
    if ctx.json {
        let rows: Vec<Value> = rows
            .into_iter()
            .map(|(id, t, v, title)| json!({ "id": id, "type": t, "vault": v, "title": title }))
            .collect();
        crate::out!("{}", Value::Array(rows));
    } else {
        let width = rows.iter().map(|r| r.1.chars().count()).max().unwrap_or(0);
        for (id, t, v, title) in rows {
            crate::out!("{id}  {t:<width$}  {v}  {title}");
        }
    }
    Ok(())
}

fn join_nonempty(parts: &[&str], sep: &str) -> String {
    parts
        .iter()
        .copied()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(sep)
}

/// The text shown for a value, or `None` when the field is empty.
fn display_value(value: &FieldValue, reveal: bool) -> Option<Zeroizing<String>> {
    let secret = |s: &Zeroizing<String>| {
        if reveal {
            s.clone()
        } else {
            Zeroizing::new(MASK.to_owned())
        }
    };
    let plain = |s: &str| Zeroizing::new(s.to_owned());
    Some(match value {
        FieldValue::Empty => return None,
        FieldValue::Text(s)
        | FieldValue::Url(s)
        | FieldValue::Email(s)
        | FieldValue::Phone(s)
        | FieldValue::Menu(s) => plain(s),
        FieldValue::Concealed(s)
        | FieldValue::Password(s)
        | FieldValue::Otp(s)
        | FieldValue::Mnemonic(s) => secret(s),
        FieldValue::Number(n) => plain(&n.to_string()),
        FieldValue::Date(d) => plain(&format!(
            "{:04}-{:02}-{:02}",
            d.year(),
            u8::from(d.month()),
            d.day()
        )),
        FieldValue::MonthYear { year, month } => plain(&format!("{month:02}/{year:04}")),
        FieldValue::Money {
            minor_units,
            currency,
        } => plain(&format!("{minor_units} {currency} (minor units)")),
        FieldValue::Address(a) => plain(&join_nonempty(
            &[
                &a.line1,
                &a.line2,
                &a.postal_code,
                &a.city,
                &a.region,
                &a.country,
            ],
            ", ",
        )),
        FieldValue::Passkey(p) => plain(&format!("{} ({})", p.rp_id, p.user_name)),
        FieldValue::SshKey(k) => {
            if reveal {
                k.private_pem.clone()
            } else {
                plain(&format!("{} (private key hidden)", k.fingerprint_sha256))
            }
        }
        FieldValue::File(f) => plain(&format!("{} ({} bytes)", f.name, f.size)),
        FieldValue::Location(l) => plain(&l.label),
        FieldValue::Barcode { value, .. } => plain(value),
        FieldValue::ItemLink(id) => plain(&id.to_string()),
    })
}

fn get(
    ctx: &Ctx,
    repo: &mut Repository<SqliteStore>,
    key: &str,
    vault: Option<&str>,
    reveal: bool,
) -> Result<(), CliError> {
    let vaults = all(repo)?;
    let (vi, item) = find_item(repo, &vaults, vault, key)?;
    let vault_name = &vaults[vi].meta.name;
    // Notes are free text and may hold secrets: masked like a secret field.
    let notes = if item.notes.is_empty() || reveal {
        item.notes.clone()
    } else {
        MASK.to_owned()
    };
    if ctx.json {
        let mut fields = Vec::new();
        for section in &item.sections {
            for f in &section.fields {
                let value = display_value(&f.value, reveal).map(|v| (*v).clone());
                fields.push(json!({
                    "section": section.id,
                    "id": f.id,
                    "label": f.label,
                    "type": format!("{:?}", f.kind),
                    "value": value,
                }));
            }
        }
        let urls: Vec<&str> = item.urls.iter().map(|u| u.url.as_str()).collect();
        crate::out!(
            "{}",
            json!({
                "id": item.id.to_string(),
                "vault": vault_name,
                "type": type_name(item.item_type),
                "title": item.title,
                "urls": urls,
                "notes": notes,
                "fields": fields,
            })
        );
        return Ok(());
    }
    crate::out!("{}", item.title);
    crate::out!("  id:    {}", item.id);
    crate::out!("  vault: {vault_name}");
    crate::out!("  type:  {}", type_name(item.item_type));
    for u in &item.urls {
        crate::out!("  url:   {}", u.url);
    }
    for section in &item.sections {
        let shown: Vec<_> = section
            .fields
            .iter()
            .filter_map(|f| display_value(&f.value, reveal).map(|v| (f, v)))
            .collect();
        if shown.is_empty() {
            continue;
        }
        crate::out!("{}", section.label);
        for (f, v) in shown {
            crate::out!("  {} [{}]: {}", f.label, f.id, *v);
        }
    }
    if !notes.is_empty() {
        crate::out!("Notes: {notes}");
    }
    Ok(())
}

fn create(
    ctx: &Ctx,
    repo: &mut Repository<SqliteStore>,
    item_type: ItemType,
    title: &str,
    fields: &[String],
    vault: Option<&str>,
) -> Result<(), CliError> {
    let vaults = all(repo)?;
    let vi = match vault {
        Some(v) => find_vault(&vaults, v)?,
        None => find_vault(&vaults, "Personnel")
            .or_else(|e| if vaults.len() == 1 { Ok(0) } else { Err(e) })?,
    };
    let mut item = new_item(item_type, vaults[vi].id, title);
    for spec in fields {
        apply_field(&mut item, spec)?;
    }
    let id = item.id;
    stored(repo.save_item(&vaults[vi], item))?;
    if ctx.json {
        crate::out!("{}", json!({ "id": id.to_string() }));
    } else {
        crate::out!("created {id}");
    }
    Ok(())
}

fn edit(
    repo: &mut Repository<SqliteStore>,
    key: &str,
    fields: &[String],
    vault: Option<&str>,
) -> Result<(), CliError> {
    let vaults = all(repo)?;
    let (vi, mut item) = find_item(repo, &vaults, vault, key)?;
    for spec in fields {
        apply_field(&mut item, spec)?;
    }
    item.updated_at = OffsetDateTime::now_utc();
    stored(repo.save_item(&vaults[vi], item))?;
    Ok(())
}

/// Set the field named by an `id=value` argument.
fn apply_field(item: &mut Item, spec: &str) -> Result<(), CliError> {
    let (id, raw) = spec
        .split_once('=')
        .ok_or_else(|| CliError::usage("a field must be written id=value"))?;
    let field = item
        .field_mut(id)
        .ok_or_else(|| CliError::usage(format!("this item has no field '{id}'")))?;
    field.value = parse_value(field.kind, id, raw)?;
    Ok(())
}

fn parse_value(kind: FieldType, id: &str, raw: &str) -> Result<FieldValue, CliError> {
    let secret = || Zeroizing::new(raw.to_owned());
    let bad = |expected: &str| CliError::usage(format!("field '{id}' expects {expected}"));
    Ok(match kind {
        FieldType::Text => FieldValue::Text(raw.to_owned()),
        FieldType::Url => FieldValue::Url(raw.to_owned()),
        FieldType::Email => FieldValue::Email(raw.to_owned()),
        FieldType::Phone => FieldValue::Phone(raw.to_owned()),
        FieldType::Menu => FieldValue::Menu(raw.to_owned()),
        FieldType::Password => FieldValue::Password(secret()),
        FieldType::Concealed => FieldValue::Concealed(secret()),
        FieldType::Otp => FieldValue::Otp(secret()),
        FieldType::Mnemonic => FieldValue::Mnemonic(secret()),
        FieldType::Number => {
            FieldValue::Number(raw.trim().parse().map_err(|_| bad("a whole number"))?)
        }
        FieldType::Date => parse_date(raw).ok_or_else(|| bad("a date as YYYY-MM-DD"))?,
        FieldType::MonthYear => parse_month_year(raw).ok_or_else(|| bad("MM/YYYY"))?,
        FieldType::Money
        | FieldType::Address
        | FieldType::Passkey
        | FieldType::SshKey
        | FieldType::File
        | FieldType::Location
        | FieldType::Barcode
        | FieldType::ItemLink => {
            return Err(CliError::usage(format!(
                "field '{id}' ({kind:?}) is not supported by the dev CLI yet"
            )));
        }
    })
}

fn parse_date(raw: &str) -> Option<FieldValue> {
    let mut it = raw.trim().split('-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let month = Month::try_from(m.parse::<u8>().ok()?).ok()?;
    Date::from_calendar_date(y.parse().ok()?, month, d.parse().ok()?)
        .ok()
        .map(FieldValue::Date)
}

fn parse_month_year(raw: &str) -> Option<FieldValue> {
    let (m, y) = raw.trim().split_once('/')?;
    if m.len() != 2 || y.len() != 4 {
        return None;
    }
    let month: u8 = m.parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    Some(FieldValue::MonthYear {
        year: y.parse().ok()?,
        month,
    })
}
