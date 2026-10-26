use onepass_core::model::FieldValue;
use onepass_core::reference::SecretRef;

use super::item::find_item;
use crate::session::{CliError, Ctx, stored, with_session};

/// `onepass totp <id|name>`: the current code of the item's one-time
/// password field.
pub fn run(ctx: &Ctx, key: &str, vault: Option<&str>) -> Result<(), CliError> {
    let code = with_session(ctx, |repo| {
        let vaults = super::vault::all(repo)?;
        let (vi, item) = find_item(repo, &vaults, vault, key)?;
        let has_otp = item
            .sections
            .iter()
            .flat_map(|s| s.fields.iter())
            .any(|f| matches!(&f.value, FieldValue::Otp(v) if !v.trim().is_empty()));
        if !has_otp {
            return Err(CliError::not_found("this item has no one-time password"));
        }
        // Ids, not names: they cannot be ambiguous.
        let r = SecretRef {
            vault: vaults[vi].id.to_string(),
            item: item.id.to_string(),
            section: None,
            field: "totp".to_owned(),
        };
        stored(repo.resolve(&r))
    })?;
    if ctx.json {
        println!("{}", serde_json::json!({ "code": *code }));
    } else {
        println!("{}", *code);
    }
    Ok(())
}
