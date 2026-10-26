//! `onepass`: development CLI over `onepass-core` (milestone 1).
//!
//! Dev mode: the Secret Key sits in clear in `<data-dir>/device.bin`, and
//! every command that touches the data directory says so on stderr.
//! Exit codes: 0 success, 1 usage error, 2 wrong password, 3 integrity
//! error, 4 not found, 5 concurrent write (nothing was saved, retry).
//! Commands that open the data directory hold its lock (`<data-dir>/lock`)
//! for their whole run, so 5 only comes from a writer that bypasses it.

mod commands;
mod session;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use commands::generate::GenerateArgs;
use commands::item::ItemCmd;
use commands::vault::VaultCmd;
use session::{CliError, Ctx};

#[derive(Parser)]
#[command(
    name = "onepass",
    version,
    about = "OnePass development CLI (dev mode)"
)]
struct Cli {
    /// Data directory (default: ~/.onepass-dev).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Print JSON instead of text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the account of this data directory.
    #[command(subcommand)]
    Account(AccountCmd),
    /// List and create vaults.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Work with items.
    #[command(subcommand)]
    Item(ItemCmd),
    /// Print a secret by reference: onepass://vault/item/[section/]field.
    Read { reference: String },
    /// Generate a password, passphrase or PIN (no account needed).
    Generate(GenerateArgs),
    /// Print the current one-time code of an item.
    Totp {
        /// Item id or title.
        key: String,
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Subcommand)]
enum AccountCmd {
    /// Create the account and show its Secret Key once.
    Create,
}

fn default_data_dir() -> Result<PathBuf, CliError> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".onepass-dev"))
        .ok_or_else(|| CliError::usage("HOME is not set; pass --data-dir"))
}

fn run(cli: Cli) -> Result<(), CliError> {
    // `generate` needs no data directory: no banner, no directory.
    if let Command::Generate(args) = cli.command {
        let ctx = Ctx {
            data_dir: PathBuf::new(),
            json: cli.json,
        };
        return commands::generate::run(&ctx, args);
    }
    let ctx = Ctx {
        data_dir: match cli.data_dir {
            Some(d) => d,
            None => default_data_dir()?,
        },
        json: cli.json,
    };
    ctx.banner();
    match cli.command {
        Command::Account(AccountCmd::Create) => commands::account::create(&ctx),
        Command::Vault(c) => commands::vault::run(&ctx, c),
        Command::Item(c) => commands::item::run(&ctx, c),
        Command::Read { reference } => commands::read::run(&ctx, &reference),
        Command::Totp { key, vault } => commands::totp::run(&ctx, &key, vault.as_deref()),
        Command::Generate(_) => unreachable!("handled above"),
    }
}

fn main() -> ExitCode {
    // clap exits with 2 on a bad command line; 2 means wrong password here.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = if e.use_stderr() { 1 } else { 0 };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        // Stdout closed by its reader: stop without a word.
        Err(e) if e.code == 0 => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e.msg);
            ExitCode::from(u8::try_from(e.code).unwrap_or(1))
        }
    }
}
