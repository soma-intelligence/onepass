use clap::Args;
use onepass_core::generator::{CharsetOptions, PassphraseOptions, Recipe, Wordlist, generate};

use crate::session::{CliError, Ctx};

#[derive(Args)]
pub struct GenerateArgs {
    /// Length of a random password (8 to 100).
    #[arg(long, default_value_t = 20, conflicts_with_all = ["words", "pin"])]
    length: u8,
    /// Leave symbols out of a random password.
    #[arg(long, conflicts_with_all = ["words", "pin"])]
    no_symbols: bool,
    /// Make a passphrase of this many words (3 to 20).
    #[arg(long, conflicts_with = "pin")]
    words: Option<u8>,
    /// Make a PIN of this many digits (4 to 12).
    #[arg(long)]
    pin: Option<u8>,
}

pub fn run(ctx: &Ctx, a: GenerateArgs) -> Result<(), CliError> {
    let recipe = match (a.words, a.pin) {
        (Some(words), _) => Recipe::Passphrase(PassphraseOptions {
            words,
            separator: "-".into(),
            capitalize: false,
            include_digit: false,
            list: Wordlist::EffEnglish,
        }),
        (None, Some(digits)) => Recipe::Pin { digits },
        (None, None) => Recipe::Random(CharsetOptions {
            length: a.length,
            lower: true,
            upper: true,
            digits: true,
            symbols: !a.no_symbols,
            avoid_ambiguous: false,
        }),
    };
    let value = generate(&recipe)?;
    if ctx.json {
        crate::out!("{}", serde_json::json!({ "value": *value }));
    } else {
        crate::out!("{}", *value);
    }
    Ok(())
}
