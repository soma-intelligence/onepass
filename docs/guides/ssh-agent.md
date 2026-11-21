# How to use OnePass as an SSH agent

OnePass includes an SSH agent that signs with Ed25519, ECDSA P-256/384/521 and RSA 3072/4096 keys stored in your vaults, generated or imported in the app. Every signature asks for your approval, or you can allow a key for 5, 15 or 60 minutes. Agent forwarding is refused by default. On the Mac it lives in Settings > Developer and stops as soon as the app locks; for development and Linux, the `onepass ssh-agent` command runs the same agent from the CLI.

## With the development CLI

```bash
onepass ssh-key generate --title "GitHub" --type ed25519 --host github.com --agent
onepass ssh-key import ~/.ssh/id_ed25519 --title "Server" --agent --confirm-each-use
onepass ssh-key public GitHub
onepass ssh-key bookmark add GitHub "*.example.com"
onepass ssh-key config --out ~/.onepass-ssh
onepass ssh-agent                     # prints SSH_AUTH_SOCK=<path> on stderr
export SSH_AUTH_SOCK=<path>
```

- The agent runs in the foreground, asks for the master password on `/dev/tty`, and serves the protocol on a Unix socket (default `<data-dir>/ssh-agent.sock`, folder `0700`, socket `0600`).
- `ssh-key config --out <dir>` writes `<dir>/config` (`Host`, `IdentityFile`, `IdentitiesOnly yes`, `IdentityAgent`) and the public keys, then prints the `Include` line to add. It never touches `~/.ssh/config`.
- Options: `--socket <path>`, `--allow-forwarded` (forwarding with an approval for every signature), `--known-hosts <file>`.

## What you approve

Each approval shows the key title and SHA-256 fingerprint, the requesting process (pid and executable, read from the kernel: `LOCAL_PEERPID` and `LOCAL_PEERTOKEN` on macOS, `SO_PEERCRED` on Linux), the destination when the connection is bound, whether it is forwarded, and the namespace for an `SSHSIG` signature (`git`, `file`). A remembered approval covers one key, one code identity and one bound destination, for at most 1 hour, and ends on `LOCK`. `--confirm-each-use` forbids remembering for that key.

## Supported keys

| Action | Supported |
|---|---|
| Generate | `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-3072`, `rsa-4096` |
| Import | OpenSSH (unencrypted, or AES in CTR, CBC or GCM with bcrypt-pbkdf), unencrypted PEM PKCS#8, PKCS#1 or SEC1 |
| RSA signatures | `rsa-sha2-256`, `rsa-sha2-512` only; SHA-1 `ssh-rsa` refused |
| Not supported | `chacha20-poly1305@openssh.com` encrypted keys, encrypted PEM, SSH certificates, FIDO `sk-*` keys, `restrict-destination` |

RSA 2048 is refused at generation (3072 minimum) and accepted at import. The import passphrase is asked on the terminal and never kept; the key is stored in the vault, which encrypts it.

## Protections

- The private key is read from the vault for each signature, used and zeroized. It never leaves the process. Signing uses `aws-lc-rs`; the `rsa` crate (RUSTSEC-2023-0071) is not used.
- `session-bind@openssh.com` is verified, and a false host signature closes the connection.
- `ADD_IDENTITY` and `REMOVE_IDENTITY` answer `FAILURE`: keys come from the vault only.
- Messages are capped at 256 KiB, decoding is strict, and a peer with another uid is refused.
- Every signature lands in the same signed, hash-chained audit log as MCP requests, and the item's key usage log shows where its secret was used.

## Related

- [Let an AI agent use a password without seeing it](mcp-server-ai-agents.md)
- [OnePass command line (CLI)](command-line-cli.md)
- [README](../../README.md)
