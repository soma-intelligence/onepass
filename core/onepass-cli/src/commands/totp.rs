use onepass_core::Error;
use onepass_core::model::KeyUseAction;
use onepass_core::reference::{SecretRef, otp_field_of};

use super::item::{find_item, note_cli_use};
use crate::session::{CliError, Ctx, stored, with_session};

/// `onepass totp <id|name>`: the current code of the item's one filled
/// one-time password field, chosen as `onepass://.../totp` chooses it.
pub fn run(ctx: &Ctx, key: &str, vault: Option<&str>) -> Result<(), CliError> {
    with_session(ctx, |repo| {
        let vaults = super::vault::all(repo)?;
        let (vi, item) = find_item(repo, &vaults, vault, key)?;
        let label = match otp_field_of(&item) {
            Ok(f) => f.label.clone(),
            Err(Error::NotFound) => {
                return Err(CliError::not_found("this item has no one-time password"));
            }
            Err(e) => return Err(CliError::from(e)),
        };
        // Ids, not names: they cannot be ambiguous.
        let r = SecretRef {
            vault: vaults[vi].id.to_string(),
            item: item.id.to_string(),
            section: None,
            field: "totp".to_owned(),
        };
        let code = stored(repo.resolve(&r))?;
        if ctx.json {
            crate::out!("{}", serde_json::json!({ "code": *code }));
        } else {
            crate::out!("{}", *code);
        }
        note_cli_use(repo, &vaults[vi], item.id, KeyUseAction::Totp, &label);
        Ok(())
    })
}
