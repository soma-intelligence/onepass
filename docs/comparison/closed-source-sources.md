# Sources for the closed source comparison in the README

All pages were read on 2026-11-02. Several vendor pages (NordPass, parts of Dashlane, LastPass and Keeper) refused automated fetches, so some claims rest on the vendor page as quoted by a search result. Where a number could not be read from the vendor's page, the README says so and does not state it. Vendor claims are the vendor's own: none of them was tested by us.

Rule used in the README: "not public" or "not found" means the vendor pages reviewed did not say. It does not mean the feature is absent.

## 1Password
- Security overview, independent audits and bug bounty: https://1password.com/security
- Encryption design (AES-GCM-256, PBKDF2-HMAC-SHA256, 128-bit Secret Key, SRP): https://support.1password.com/1password-security/
- Plans, platforms, passkeys, sharing, list prices ($3.99 Individual, $5.99 Families a month, billed yearly): https://1password.com/pricing/password-manager
- Travel Mode, every plan: https://support.1password.com/travel-mode/
- AI agents (Secure Agentic Autofill, MCP server for Environments): https://www.1password.dev/get-started/secure-ai-access
- 2023 Okta incident statement (22 Oct 2023, updated 25 Oct 2023): https://1password.com/blog/okta-incident

## NordPass
- Security, Argon2id, XChaCha20-Poly1305, Cure53 and ISO 27001 / SOC 2 Type 2 claims: https://nordpass.com/security/
- Platforms, passkeys, Family plan: https://nordpass.com/family-password-manager/ and https://nordpass.com/download/linux/
- Audit history (secondary): https://www.technadu.com/cure53-audit-nordpass-verify-robust-security/101714/

## Dashlane
- Argon2d parameters, AES-256-CBC + HMAC-SHA256, zero-knowledge claim: https://www.dashlane.com/security
- Post-quantum is a prototype, not shipped (15 Nov 2022, updated 18 Oct 2024): https://www.dashlane.com/blog/preparing-for-the-quantum-world
- Passkeys and platforms: https://support.dashlane.com/hc/en-us/articles/32830330815762-Create-and-save-a-passkey-using-Dashlane
- Plans, annual billing only, Friends and Family of 10: https://support.dashlane.com/hc/en-us/articles/360001166969-Compare-Dashlane-personal-plans
- Business features: https://www.dashlane.com/pricing
- MCP server, audit logs, beta: https://www.dashlane.com/blog/mcp-server-audit-log-access
- Brute-force advisory (date not retrieved): https://support.dashlane.com/hc/en-us/articles/36038764990866-Security-advisory-Brute-force-attack-on-Dashlane-user-accounts

## Keeper
- Security overview, pen tests by NCC Group and Cybertest, certifications: https://www.keepersecurity.com/security.html
- Encryption model (PBKDF2 1,000,000 iterations, AES-256-GCM record keys): https://docs.keeper.io/enterprise-guide/keeper-encryption-model
- Family plan, free tier: https://www.keepersecurity.com/pricing/personal-and-family.html
- Secrets Manager MCP server: https://docs.keeper.io/en/keeperpam/secrets-manager/integrations/model-context-protocol-mcp-for-ai-agents
- Agent Kit (May 2026), secondary: https://www.techpartner.news/news/keeper-security-launches-suite-of-specialised-ai-skills-626112

## LastPass
- Zero-knowledge model, PBKDF2-SHA256 600,000 iterations, AES-256: https://www.lastpass.com/security/zero-knowledge-security
- Iteration migration, Argon2 and AES-GCM rollout (July 2024 bulletin): https://support.lastpass.com/help/what-have-we-done-to-ensure-lastpass-is-safe-to-use
- SOC 2 and ISO 27001/27701 audits: https://www.lastpass.com/company/newsroom/da86056a-167c-4e6f-a506-b99d07c30501
- Plans and passkeys: https://www.lastpass.com/pricing
- Free plan changes: https://blog.lastpass.com/posts/changes-to-lastpass-free
- 2022 breach, Schneier (Dec 2022): https://www.schneier.com/blog/archives/2022/12/lastpass-breach.html
- 2022 breach, Help Net Security: https://www.helpnetsecurity.com/?p=251654
- 2022 breach, overview and 2025 class action settlement: https://en.wikipedia.org/wiki/2022_LastPass_data_breach

## Apple Passwords
- iCloud Keychain security (key protection, escrow, 10 attempts): https://support.apple.com/guide/security/icloud-keychain-security-overview-sec1c89c6f3b/web
- End-to-end encrypted categories: https://support.apple.com/en-us/102651
- Passwords app, passkeys, shared groups, OS versions: https://support.apple.com/en-us/120758
- Windows access: https://support.apple.com/guide/icloud-windows/set-up-icloud-passwords-icw2babf5e03/icloud

## Proton Pass (open source)
- Open source and audits (Cure53 2023): https://proton.me/blog/pass-open-source-security-audit
- Security model, bcrypt key wrapping: https://proton.me/blog/proton-pass-security-model
- Recurity Labs audit, Jan to Apr 2026: https://proton.me/business/pass/security
- AI access tokens (21 May 2026): https://proton.me/blog/pass-access-tokens

## OnePass
- 2026-10-28 security comparison with 11 open source managers (desk review, OnePass scored from code, peers from public evidence): kept by the maintainers, summarized in the README.
- Everything in the OnePass rows is from this repository: README feature list, `docs/security/README.md`, and the roadmap. Sharing, mailbox, multi-account and travel detection are marked in progress because they are not in a release.
