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
