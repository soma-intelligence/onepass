# Has Cleon been security audited?

No. As of November 2026, Cleon **has not had an external security audit**; one is planned for milestone 8 on the [roadmap](../../README.md#roadmap). The design, formal models and tests are public, but no outside firm has reviewed them. The README asks you to weigh that before Cleon holds your only copy of a secret, and to keep an encrypted export.

## What exists instead of an audit

| Evidence | Where |
|---|---|
| Full security whitepaper and threat model (in French) | [`docs/security/README.md`](../security/README.md) |
| Review of every cryptographic primitive, with versions and code references (2026-10-26, in French) | [`docs/security/crypto-review.md`](../security/crypto-review.md) |
| ProVerif models: account creation and unlock, vault manifests, Emergency Kit, extension bridge, key rotation, mailbox, including runs with one half of each hybrid KEM broken | [`formal/`](../../formal/README.md), results in [`docs/security/formal/results.md`](../security/formal/results.md) |
| NIST ACVP known-answer vectors for ML-KEM-1024, ML-DSA-87 and SLH-DSA | `core/onepass-core/tests/` |
| Differential tests: `aws-lc-rs` against `libcrux`, property tests on the AEAD | `core/onepass-core/tests/differential.rs`, `aead_props.rs` |
| 48 `cargo-fuzz` targets, 20 run in CI | `core/fuzz/` |
| A malicious store suite that replays known server-side attacks | `core/onepass-core/tests/malicious_store.rs`, `core/onepass-sync/tests/hostile_mailbox.rs` |
| A seeded autofill lab of fictional websites that counts leaks (first 200-site run: 63.8% fill rate, 0 leaks) | `extension/lab/`, [report](../lab/2026-10-26-autofill-lab-run.md) |
| Supply chain: `cargo deny`, `cargo vet`, `cargo audit`, pinned Actions, SLSA provenance | [`docs/security/release-pipeline.md`](../security/release-pipeline.md) |

Run the formal models yourself with `make formal` and the core checks with `make -C core check`.

## How Cleon scored in its own comparison

On 2026-10-28 Cleon was scored against 10 open source managers with one rubric: design (out of 40) and proof, meaning tests, releases and maturity (out of 15). Cleon scored 29 on design, tied for first, and 5 on proof, second to last. It was scored from its code, the others from public evidence, and it is a desk review rather than a penetration test. See [How Cleon compares](../../README.md#how-onepass-compares).

## Known gaps the project lists

- No `mlock` of secret memory pages (secrets are zeroized).
- Swift cannot guarantee that copies of a `String` are erased.
- Several crypto and storage crates are still exempted in `cargo vet` and wait for a human review (listed in `release-pipeline.md`).
- The Mac app build is not reproducible (signature and notarization).

## Report a vulnerability

Report privately through [GitHub private vulnerability reporting](https://github.com/soma-intelligence/onepass/security/advisories/new) or to security@somalabs.me, never in a public issue. Acknowledgement within 72 hours, first assessment within 7 days, and a fix or a dated plan within 90 days. Good faith research is covered by a safe harbor. Full policy: [SECURITY.md](../../SECURITY.md).

## Related

- [Cleon threat model](threat-model.md)
- [Post-quantum cryptography in Cleon](post-quantum-encryption.md)
- [Verify a Cleon download](verify-a-download.md)
- [README](../../README.md)
