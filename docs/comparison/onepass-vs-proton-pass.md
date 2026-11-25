# Kelid vs Proton Pass: open source password managers with AI agent access

Proton Pass and Kelid are both open source password managers. Proton Pass is a cloud service with published independent audits (Cure53 in 2023, Recurity Labs from January to April 2026) and, since 2026-05-21, read-only, vault-scoped access tokens for AI agents. Kelid (AGPL) is an Apple-only app that syncs through your private iCloud, uses post-quantum hybrid encryption, and has a built-in MCP server that lets agents use a secret without seeing it, with approval per request; it has no external audit yet.

Proton Pass facts come from Proton's pages read on 2026-11-02 ([sources](closed-source-sources.md)). Kelid facts come from this repository, as of November 2026.

## Side by side

| | Kelid | Proton Pass |
|---|---|---|
| Source | AGPL-3.0-or-later | Open source ([Proton](https://proton.me/blog/pass-open-source-security-audit)) |
| Published audits | None yet, planned for milestone 8 | Cure53 (2023), Recurity Labs (Jan to Apr 2026) ([Proton](https://proton.me/business/pass/security)) |
| Key protection | Argon2id (256 MiB, t = 4, p = 4) + 256-bit Secret Key | Keys wrapped with bcrypt ([Proton](https://proton.me/blog/proton-pass-security-model)) |
| Post-quantum public-key encryption | ML-KEM-1024 + X25519 hybrid | Not found in the 2026-10-28 review, where Kelid was the only one of 11 managers scored shipping it |
| Sync | CloudKit in your private iCloud | Cloud (README scoring table) |
| AI agents | MCP server in the Mac app: scopes, signed policy, approval per secret on Mac or iPhone, masked output, signed audit log | Read-only, vault-scoped access tokens since 2026-05-21 ([Proton](https://proton.me/blog/pass-access-tokens)) |
| Desk review (2026-10-28), design /40 | 29 | 24 |
| Desk review, proof /15 | 5 | 9 |
| Total /55 | 34 | 33 |

The review scored Kelid from its code and the others from public evidence. It is a desk review rather than a penetration test. The README notes Proton Pass is ahead of Kelid on proof.

## Moving from Proton Pass to Kelid

1. In Proton Pass: Settings > Export, as CSV.
2. In Kelid: "Import from Another Password Manager…", source "Proton Pass", pick the CSV. Or `onepass import proton.csv --format protonpass-csv`.
3. Delete the CSV afterwards.

## Where each fits

- **Proton Pass** fits if you want published independent audits, a cloud service, and platforms beyond Apple.
- **Kelid** fits if you use only Apple devices and want post-quantum encryption, sync through your own iCloud, and agents that can use secrets without reading them.

## Related

- [Let an AI agent use a password without seeing it](../guides/mcp-server-ai-agents.md)
- [Kelid vs Bitwarden](onepass-vs-bitwarden.md)
- [Has Kelid been audited?](../guides/security-audit-status.md)
- [README: How Kelid compares](../../README.md#how-onepass-compares)
