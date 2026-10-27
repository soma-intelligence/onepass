# Security policy

OnePass is a password manager. A flaw in it directly affects the people who use it, so we would much rather hear about one through a private report than read about it in public.

## Reporting a vulnerability

Don't open a public issue, pull request or discussion for a security problem. Report it privately instead:

- through [GitHub private vulnerability reporting](https://github.com/soma-intelligence/onepass/security/advisories/new) (Security tab, "Report a vulnerability");
- or by email to **security@somalabs.me**.

Please include:

- the version or commit, the platform and the OS version;
- what the flaw is and what it lets an attacker do (which data, which attacker, which conditions);
- steps to reproduce, ideally with synthetic data, never a real vault;
- a proof of concept if you have one, and any ideas for a fix;
- the name to credit, if you want credit.

## Timelines

- Acknowledgement within 72 hours.
- First assessment (confirmed or not, estimated severity) within 7 days.
- A fix released, or a dated fix plan shared with you, within 90 days.

If a flaw is already being exploited, we ship a fix or a mitigation as soon as we can, without waiting for the end of that window.

## Coordinated disclosure

Please don't publish anything before a fix is available or 90 days have passed, whichever comes first. If we can't meet that window, we'll tell you and agree on a date together. Reporters are credited in the security advisory unless they ask otherwise.

## Safe harbor for good faith research

We won't take legal action against, or ask for prosecution of, anyone who looks for and reports a flaw in good faith and follows these rules:

- test only your own accounts, devices and data, or synthetic data;
- don't access, change or destroy other people's data;
- don't degrade a shared service (no denial of service, no load testing against CloudKit or third party infrastructure);
- no social engineering and no physical attacks against people;
- give us the window above before publishing.

## In scope

- The Rust core (`core/`): cryptography, vault format, sync, restore epochs, import and export, archives.
- The Apple apps (`apple/`): iPhone, iPad, Mac, Apple Watch and Vision Pro, the AutoFill provider, widgets.
- The browser extension (`extension/`) and the native messaging host (`core/onepass-native-host`, `core/onepass-bridge`).
- The command line and the local interfaces (`core/onepass-cli`, `core/onepass-ffi`, `core/onepass-mcp`, `core/onepass-ssh-agent`).
- The build chain: GitHub Actions workflows, dependencies, signatures.

The threat model and the guarantees we aim for are described in [docs/security/README.md](docs/security/README.md).

## Out of scope

- Attacks that need a device already compromised at the system level (root, kernel, the owner debugging the app), or physical access to an unlocked device.
- A weak or reused master password chosen by the user.
- Platform flaws (iOS, macOS, browsers, CloudKit) unrelated to our code: report those to the vendor.
- Reports from automated tools without a demonstrated impact, and headers or settings without a demonstrated consequence.
- Phishing and social engineering.
- Limits already documented in `docs/security/README.md` and in the design specs under `docs/specs/`, such as the dev CLI keeping its Secret Key in clear.

## Supported versions

OnePass has no 1.0 release yet. Only `main` receives security fixes. After 1.0, this section will list the maintained versions.

OnePass has not had an external audit yet. One is planned before the first stable release.

## Supply chain

Dependencies are checked with `cargo deny`, `cargo vet` and `npm audit`, and GitHub Actions are pinned by commit SHA. See `docs/security/reproducible-builds.md`.
