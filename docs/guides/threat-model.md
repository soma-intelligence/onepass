# What does Kelid protect against? The threat model in plain English

Kelid treats its own sync storage as the main adversary: iCloud (CloudKit), a future server, the network or a stolen disk may modify, replay, delete, reorder or inject records, and the app must detect it and refuse the data. Hostile web pages, compromised browser renderers and untrusted AI agents are also in scope. A device compromised at the operating system level (root, jailbreak) and an attacker who reads process memory are out of scope. The full model is in [`docs/security/README.md`](../security/README.md) (in French) and [`SECURITY.md`](../../SECURITY.md).

## What the storage can see

For every record the server learns its id, type, version number and padded blob size. It can count items per vault and tell which vault each item belongs to, and it sees manifest sequence numbers and write timing. It never sees titles, URLs, item types, tags, field counts or contents. On iCloud, records live in your private CloudKit database, zone `Kelid`, record type `OPRecord`.

## What Kelid guarantees against a hostile storage

- Confidentiality of item contents and metadata.
- Detection of an item that was deleted, injected, replayed in an older version, moved to another vault or swapped with another.
- Detection of a vault rolled back or forked: every vault has a signed, hash-chained manifest with a Merkle root, and each device remembers the last manifest it saw (sequence number and hash).
- Refusal of weakened or unsigned Argon2id parameters (the floor is 256 MiB, t = 4, p = 4).
- Refusal of a substituted vault key: a vault is listed only if its signed manifest opens with the key received.
- No silent loss between two concurrent writes: the manifest write is conditional and the loser gets `Conflict`.

When an integrity check fails, the app shows a "Data Refused" screen with the type of attack and never repairs the storage on its own. A test suite replays every known server-side attack (`core/onepass-core/tests/malicious_store.rs` and `core/onepass-sync/tests/hostile_mailbox.rs`).

## Other attackers in scope

| Attacker | Defense, in short |
|---|---|
| A hostile web page (invisible fields, clickjacking, lookalike domains, foreign iframes) | Fill only on HTTPS origins that match by registrable domain (Public Suffix List), never in payment iframes from other sites, origin taken from the browser, never from the page |
| A compromised renderer | The extension's service worker trusts only the origin the browser reports |
| Another local process or extension | The bridge serves only a peer that holds a pairing key; the Mac app checks the code signature of every client |
| An AI agent, or a prompt injection it reads | Signed MCP policy, scopes, an approval for every secret, values masked in output, signed audit log |
| A lost iPhone used to approve agent requests | Every answer needs Face ID through a `.biometryCurrentSet` key |

## Out of scope, stated by the project

- A device compromised at OS level, or physical access to an unlocked device.
- Reading process memory: secrets are zeroized, but `mlock` is not implemented.
- Traffic analysis beyond size-tier padding.
- A weak or reused master password chosen by the user.
- Platform flaws in iOS, macOS, browsers or CloudKit.

## Known gaps the project lists itself

- No external audit yet ([details](security-audit-status.md)).
- Swift cannot guarantee that copies of a `String` are erased.
- Software that reads the browser profile obtains the extension's pairing key and can request secrets for specific origins, like the extension itself.
- The development CLI with `--insecure-file-secret-key` keeps the Secret Key in clear in `device.bin`.

## Related

- [Post-quantum cryptography in Kelid](post-quantum-encryption.md)
- [How sync through iCloud works and what Apple sees](icloud-sync.md)
- [Has Kelid been audited?](security-audit-status.md)
- [How to report a vulnerability](../../SECURITY.md)
- [README](../../README.md)
