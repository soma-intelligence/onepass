use std::io::{IsTerminal, Write};

use onepass_core::model::{Item, KeyUseAction};
use onepass_core::reference::{SecretRef, locate, parse_ref};
use onepass_core::repo::Repository;
use onepass_core::store::SqliteStore;
use onepass_core::vault::Vault;

use super::item::note_cli_use;
use crate::session::{CliError, Ctx, stdout_error, stored, with_session};

/// `onepass read onepass://vault/item/[section/]field`: the bare value.
pub fn run(ctx: &Ctx, reference: &str) -> Result<(), CliError> {
    let r = parse_ref(reference)?;
    with_session(ctx, |repo| {
        let value = stored(repo.resolve(&r))?;
        if ctx.json {
            crate::out!("{}", serde_json::json!({ "value": *value }));
        } else {
            let mut out = std::io::stdout().lock();
            out.write_all(value.as_bytes()).map_err(stdout_error)?;
            if out.is_terminal() {
                out.write_all(b"\n").map_err(stdout_error)?;
            }
            out.flush().map_err(stdout_error)?;
        }
        // After printing: a use the log cannot place is simply not noted.
        if let Some((vault, item, label)) = target_of(repo, &r) {
            note_cli_use(repo, &vault, item.id, KeyUseAction::Revealed, &label);
        }
        Ok(())
    })
}

/// The vault, live item and field label `r` points at, found the way
/// `resolve` finds them (id, else name ignoring case). `None` when
/// anything is missing: `resolve` has just succeeded, so this is not
/// expected.
fn target_of(repo: &mut Repository<SqliteStore>, r: &SecretRef) -> Option<(Vault, Item, String)> {
    let vault = repo.vaults().ok()?.into_iter().find(|v| {
        v.id.to_string().eq_ignore_ascii_case(&r.vault)
            || v.meta.name.eq_ignore_ascii_case(&r.vault)
    })?;
    let item = repo.items(&vault).ok()?.into_iter().find(|i| {
        i.trashed_at.is_none()
            && (i.id.to_string().eq_ignore_ascii_case(&r.item)
                || i.title.eq_ignore_ascii_case(&r.item))
    })?;
    let label = locate(&item, r).ok()?.label.clone();
    Some((vault, item, label))
}
