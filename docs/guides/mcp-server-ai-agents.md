# How to let an AI agent (Claude Code, Codex, Cursor) use a password without seeing it

Cleon ships an MCP (Model Context Protocol) server inside the Mac app that lets AI agents *use* a credential without *seeing* it: the agent runs a command with secrets injected and masked in the output, fills a template, or fills a login into a browser page, and gets back only the result. Every secret request asks you first, in a floating panel on the Mac with Touch ID or on your iPhone with Face ID, and lands in a signed, hash-chained audit log. Only vaults that a signed policy exposes exist for the agent.

## Add Cleon to an AI client in one command

```bash
/Applications/OnePass.app/Contents/Helpers/onepass-mcp install --client claude-code
```

Clients: `claude-code`, `claude-desktop`, `codex`, `cursor`. `--dry-run` shows the diff; a backup of the client config is kept and only the `onepass` entry changes. Settings > Developer on the Mac gives you the command to copy, and also a copyable `mcpServers` block for other clients.

## Choose what agents can reach

All of this lives in Settings > Developer on the Mac and stops as soon as the app locks (unless your iPhone unlocks it for agents, below).

| Scope | Tools | Approval |
|---|---|---|
| `metadata` | `list_vaults`, `list_items`, `search_items`, `get_item` | None: never a value, note or subtitle |
| `use` | `run_with_secrets`, `fill_template` | Every request, or remembered 5, 15 or 60 minutes for the exact same request |
| `write` | `create_login` | Every request |
| `totp` | `totp_code` | Every call, never remembered |
| `reveal` | `reveal_secret` | Every call, never remembered |
| `fill` (off by default) | `fill_in_browser` | Strong gesture the first time for a login; every time for a card |
| global | `generate_password` | None: the value is not in the vault |

A vault is visible to agents only if the signed MCP policy lists it. Vault or item references outside reach answer exactly like "not found", so an agent cannot probe for existence.

## How a request is approved

1. The agent calls a tool. Cleon checks arguments, visibility, scope, then asks you.
2. The Mac shows a floating panel (Touch ID); your iPhone can answer too (Face ID), whichever comes first. The agent is told a 4-letter code to match on screen.
3. The audit log records the request and where you approved it.

The core documents default limits per client (`core/README.md`, in French): 6 prompts a minute and 30 secret requests a minute, and 3 denials in a row block the client for 10 minutes.

## Running commands with secrets

`run_with_secrets` runs `argv` directly (no implicit shell), without stdin, with a 60 second default timeout (600 at most). Output is cut at 64 KiB, and every secret value of 4 characters or more is replaced by `<concealed:NAME>`, along with its base64 and hex forms. Vault data comes back under `untrusted_vault_data`, marked as data and never instructions. Masking reduces risk; it does not stop an approved command from transforming a secret. The approval, which shows the exact command and the resolved program path, is the real barrier. Interpreters such as `sh`, `python`, `node`, `npm` and `make` are never remembered.

## Filling a web form for an agent

`fill_in_browser` fills a login or a card into a Chromium page (Chrome, Edge, Brave, Arc through the extension, or any browser an agent drives over local CDP) and returns only the names of the fields filled. Turn the `fill` scope on per vault, then tick "Web fill" in the client's menu. A card is asked every time, never remembered and never submitted. A page script, or an agent that can run JavaScript in the page or read the DOM over CDP, can read what was filled, so fill only browsers you trust.

## Agents while the Mac is locked

Off by default and enrolled per Mac and iPhone pair: your iPhone can unlock a locked Mac **for agents only**. The app's own screens, AutoFill, the extension and widgets stay locked. The window lasts 1 hour by default (15 minutes to 8 hours) and ends on sleep, lock, or "Lock now" on the phone.

## The development CLI server

For development and Linux, `onepass mcp` runs the same server on stdio from the CLI, with approvals typed on the terminal (`/dev/tty`). See [the CLI guide](command-line-cli.md).

## Related

- [Use Cleon as an SSH agent](ssh-agent.md)
- [Cleon command line (CLI)](command-line-cli.md)
- [Cleon threat model](threat-model.md)
- [README: Developer tools](../../README.md#features)
