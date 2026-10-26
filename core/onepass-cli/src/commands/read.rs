use std::io::{IsTerminal, Write};

use onepass_core::reference::parse_ref;

use crate::session::{CliError, Ctx, with_session};

/// `onepass read onepass://vault/item/[section/]field`: the bare value.
pub fn run(ctx: &Ctx, reference: &str) -> Result<(), CliError> {
    let r = parse_ref(reference)?;
    let value = with_session(ctx, |repo| Ok(repo.resolve(&r)?))?;
    if ctx.json {
        println!("{}", serde_json::json!({ "value": *value }));
        return Ok(());
    }
    let mut out = std::io::stdout().lock();
    out.write_all(value.as_bytes())?;
    if out.is_terminal() {
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(())
}
