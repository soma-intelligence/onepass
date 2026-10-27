# NIST ACVP test vectors

Source: https://github.com/usnistgov/ACVP-Server, commit
`975de31eb83d87039ec88934fdc47d8c312b892d` (master, 2026-08-12).

Each file is a trimmed copy of `internalProjection.json` (prompt and expected
values joined) from `gen-val/json-files/<directory>/`, downloaded from
`https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/<directory>/internalProjection.json`.
Only the parameter set and groups listed below are kept, and only the fields
the tests read (`tcId` and the hex values; private keys `sk` and unused fields
are dropped). Hex strings are unchanged (upper case).

| File | Directory | Parameter set | Groups kept (tgId) |
| --- | --- | --- | --- |
| `mlkem1024.json` | `ML-KEM-encapDecap-FIPS203` | ML-KEM-1024 | 3 (AFT, encapsulation, 25 cases: used as decapsulation of `c` under `dk` plus deterministic encapsulation from `m`), 6 (VAL, decapsulation, 10 cases with modified ciphertexts, implicit rejection) |
| `mldsa87.json` | `ML-DSA-sigVer-FIPS204` | ML-DSA-87 | 5 (external interface, pure, 15 cases) |
| `slhdsa_sha2_256s.json` | `SLH-DSA-sigVer-FIPS205` | SLH-DSA-SHA2-256s | 23 (external, pure, 14 cases, with context), 33 (internal, 14 cases) |

Dropped on purpose: other parameter sets, ML-KEM key-check groups
(`decapsulationKeyCheck`, `encapsulationKeyCheck`), ML-DSA pre-hash,
external-mu and internal groups, SLH-DSA pre-hash groups.

## ML-DSA-87 signature generation

`mldsa87_siggen.json`: `internalProjection.json` of `ML-DSA-sigGen-FIPS204` at
the same commit, ML-DSA-87, external interface, pure, no external mu, only the
cases with an empty context (tgId 5 deterministic: 2 cases, tgId 17 hedged:
1 case). Kept fields: `tcId`, `pk`, `message`, `signature` (`sk`, `rnd` and the
rest dropped). Used to check that the expected signatures verify.

# OnePass golden vectors

`kem_wrap_key_v1.hex`: one `crypto::kem::wrap_key` envelope, generated once
by OnePass itself (milestone 6, after a byte-preserving refactor of the
combiner) and never regenerated. Lines, lower-case hex: hybrid KEM secret
(`HybridKemSecret::to_bytes`, 3200 bytes), wrapped key (32 bytes), context,
envelope. The test `kem::tests::wrap_key_golden_vector` opens it with
`unwrap_key`: vault key envelopes already on disk must keep opening.
