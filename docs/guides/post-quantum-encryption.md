# What post-quantum cryptography does Kelid use?

Kelid wraps every vault key with a hybrid of **ML-KEM-1024** (FIPS 203) and **X25519**, signs vault manifests, backups and the MCP policy with a hybrid of **ML-DSA-87** and **Ed25519** (both halves must verify), and anchors each account with an **SLH-DSA-SHA2-256s** (FIPS 205) identity key. Each hybrid combines a post-quantum and a classical algorithm, so breaking only one of them does not open the vault. The construction is in `core/onepass-core/src/crypto/` and documented in [`docs/security/README.md`](../security/README.md) (in French).

## The algorithms, by purpose

| Purpose | Algorithm | Code |
|---|---|---|
| Password hashing | Argon2id v1.3, floor m = 256 MiB, t = 4, p = 4 | `crypto/kdf.rs` |
| Key derivation | HKDF-SHA256 | `crypto/kdf.rs` |
| Blob encryption | AES-256-GCM-SIV with an HMAC-SHA256 key commitment and size-tier padding | `crypto/aead.rs` |
| Vault key wrapping | ML-KEM-1024 + X25519 hybrid KEM | `crypto/kem.rs` |
| Manifests, backups, MCP policy, audit log head | ML-DSA-87 + Ed25519 hybrid signature | `crypto/sign.rs` |
| Account root identity | SLH-DSA-SHA2-256s | `crypto/sign.rs` |
| Browser extension channel | ML-KEM-1024 + X25519, then AES-256-GCM per direction | `core/onepass-bridge` |
| Passkeys | ECDSA P-256 (ES256), as WebAuthn requires | `onepass-core::webauthn` |
| Biometric unlock | Secure Enclave P-256 key, ECIES | Apple apps |

## How the hybrid KEM combines both halves

To wrap a vault key, the core encapsulates to both the account's ML-KEM-1024 key and its X25519 key, then derives the wrapping key with:

```
HKDF-SHA256(salt = empty,
            ikm  = ss_mlkem || ss_x25519 || ct_mlkem || eph_x25519_pub || x25519_recipient,
            info = "onepass/kem/v1" || context)
```

Both shared secrets, the ciphertext, the ephemeral key and the recipient key all enter the derivation. The ProVerif models in `formal/` include runs where one half of each hybrid is assumed broken (`account_kem_mlkem_broken.pv`, `account_kem_x25519_broken.pv`), and the secrecy properties still hold. Results: [`docs/security/formal/results.md`](../security/formal/results.md).

## Why hybrid signatures need both halves

A manifest signature is 4,627 bytes of ML-DSA-87 plus 64 bytes of Ed25519. Both are always computed and both must verify, with no short circuit. A forged manifest needs a break of both schemes. SLH-DSA, a hash-based scheme, signs only the account parameters (domain `account-params`), so the account identity rests on hash function assumptions alone.

## Which libraries do the work

- Rust: `aws-lc-rs` (AES-256-GCM-SIV, HMAC, HKDF, SHA-2, SHA-3, ML-KEM-1024, X25519, ML-DSA-87, Ed25519, system RNG), `argon2`, `slh-dsa` (pinned `=0.1.0`). `libcrux-ml-kem` generates ML-KEM keys from a seed and serves as an independent reference in differential tests.
- Browser extension: WebCrypto for the symmetric parts, `@noble/post-quantum` and `@noble/curves` (exact versions) for the KEMs. Cross vectors in `core/onepass-bridge/tests/vectors/` are checked on both sides.

## How it is tested

- NIST ACVP known-answer vectors for ML-KEM-1024, ML-DSA-87 and SLH-DSA.
- Differential tests of `aws-lc-rs` against `libcrux`.
- 48 `cargo-fuzz` targets in `core/fuzz`; 20 of them run for 30 seconds each in the `core` CI workflow on every push or pull request that touches `core/`.
- ProVerif models for account creation and unlock, manifests, the Emergency Kit, the extension bridge and key rotation (`make formal`).

No outside firm has audited this code yet. See [Has Kelid been audited?](security-audit-status.md).

## What post-quantum does not cover

Passkeys stay ECDSA P-256 because websites verify them with that algorithm. iCloud transport and CloudKit's own encryption are Apple's and are not counted in the threat model. Traffic analysis beyond size-tier padding is out of scope.

## Related

- [Kelid threat model](threat-model.md)
- [Master password, Secret Key and Emergency Kit](master-password-secret-key-emergency-kit.md)
- [How sync through iCloud works](icloud-sync.md)
- [README: Security model](../../README.md#security-model)
