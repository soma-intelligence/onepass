# GHSA-8wp4-pjw5-pppg: a revoked device can make its revoker erase its local vault

Release preparation for the fix. Three parts: the final advisory text (to paste into the draft
advisory), the release notes for v0.2.1, and the owner checklist, in order. Nothing here has been
pushed, tagged or published.

| Field | Value |
| --- | --- |
| Advisory | GHSA-8wp4-pjw5-pppg (draft, soma-intelligence/onepass) |
| Severity | Medium |
| Weakness | CWE-285, Improper Authorization |
| Package | ecosystem "other", name `onepass` |
| Affected | `>= 0.2.0, < 0.2.1` (source on `main` from 89ad2a36 to 8661a566; never tagged) |
| Patched | `0.2.1` |
| Fix commit | `fix(devices): lock a device the list marks revoked, never erase it` on `release/advisory-fix` |
| CVE | to request from GitHub when publishing |

---

## 1. Advisory text

**Title:** A revoked device can make the device that revoked it erase its local vault

### Summary

OnePass signs the device list with account keys that every device of the account holds, a revoked
device included. A revoked device that has not yet seen its own revocation (for example because it
was offline) can mark the device that revoked it as revoked too. The device list merge is monotone,
so both revocations are kept. In the affected code, a device that finds itself marked revoked erases
its local OnePass data at its next unlock or sync. A device the user revoked can therefore make a
legitimate device erase itself.

### Impact

- **What is lost:** the local copy of the vault on the targeted device (availability). Anything
  that device had not synced yet is lost with it.
- **What is not affected:** no secret is disclosed and no key is changed. The encrypted records in
  the user's iCloud zone and on the account's other devices are not touched, so the vault comes back
  with the Secret Key and the master password, or by pairing again.
- **Who can do it:** only a device that was once part of the account, because it needs the account
  keys. No modified client is needed: revoking device A from device B while B is offline and has not
  yet learned that A revoked it is enough.

### Affected versions

- **Affected:** `>= 0.2.0, < 0.2.1`. Device revocation with automatic erase first appeared in the
  0.2.0 source on `main`, commit `89ad2a36` ("OnePass v0.2.0", 2026-10-28), and stayed through
  `e8993759` and `8661a566`. 0.2.0 was never tagged or released as a binary on GitHub, so this only
  concerns people who built `main` themselves between those commits.
- **Not affected:** every tagged release, v0.1.0 to v0.1.4. Their core already has the signed device
  list, but no app or tool in them erases a device that the list marks revoked.

### Patches

Fixed in **0.2.1**. A device the list marks revoked is now locked, never erased: the session is
dropped, the state stays "revoked" across launches, and the encrypted data stays on the device. Only
the user can erase it, from the revoked screen, after a confirmation that warns that the device may
have been marked by a device that was itself revoked. Regression tests cover the self-revocation
race (`revoked_device_can_revoke_its_revoker`), the lock at sync and at unlock, the retry of a
failed erase, and check that erasing a revoked device leaves the iCloud zone and the other devices
unchanged.

The root cause, a device list signed with keys a revoked device still holds, is addressed by the key
rotation v2 design (trust anchored in per-device keys), which is not shipped yet. Until then a
revoked device can still mark other devices revoked; with 0.2.1 that only locks them and shows the
revoked screen, and the user decides.

### Workarounds

If you cannot update yet:

- keep an export of the vault outside OnePass and keep your Emergency Kit;
- after revoking a device, make sure it cannot come back online with OnePass unlocked (wipe it, or
  keep it off the network);
- if a device you did not revoke shows the revoked screen, do not unlock or sync it again before
  updating; check the device list from another device.

### Credits

- Found by: `<CREDIT PLACEHOLDER: name or "the OnePass team">`

### Timeline

- 2026-10-28: 0.2.0 source with device revocation and automatic erase pushed to `main` (89ad2a36).
- 2026-10-29: issue found and reproduced with unmodified code; fix written on the private
  development repository.
- 2026-10-30: draft advisory GHSA-8wp4-pjw5-pppg opened; fix backported onto public `main`.
- `<DATE>`: 0.2.1 released, advisory published, CVE requested.

---

## 2. Release notes: OnePass v0.2.1

**Why 0.2.1 and not 0.2.0 or 0.1.5.** The vulnerable code already carries version 0.2.0 everywhere
(`core/Cargo.toml`, `MARKETING_VERSION`, the extension manifest), so anyone who built `main` has a
"0.2.0" that is affected. Tagging the fix as v0.2.0 would make that number mean both the affected and
the fixed build, and the advisory range could not tell them apart. 0.1.5 would sit below code that
already says 0.2.0, and 0.1.x never had the automatic erase. 0.2.1 gives one clean range: affected `>= 0.2.0, < 0.2.1`, patched `0.2.1`.

Paste below as the release body.

```markdown
A security fix on top of the 0.2.0 source, and the first tagged 0.2 release.

> **Pre-release.** OnePass has not had an external security audit yet. Please don't store real secrets in it until the first audited release. Security reports: see [SECURITY.md](https://github.com/soma-intelligence/onepass/blob/main/SECURITY.md).

## Security
- **GHSA-8wp4-pjw5-pppg (medium):** a revoked device could make the device that revoked it erase its local vault. A device the signed device list marks revoked is now locked, never erased: its encrypted data stays, the revoked screen stays across launches, and only you can erase it, after a confirmation. Affected: 0.2.0 built from `main` (never tagged). Not affected: v0.1.0 to v0.1.4. Details in the advisory.

## Downloads
- **Mac:** `OnePass-0.2.1-mac.zip`, signed with Developer ID and notarized.
- **Chrome:** `OnePass-0.2.1-chrome.zip`, for review and testing only.
- `SHA256SUMS` lists the checksum of every file.

## Known limits
- No external audit yet.
- A revoked device can still mark other devices revoked until key rotation v2 ships (trust anchored in per-device keys). With this release that only locks the marked device; check your device list before erasing it.
- The limits listed for v0.1.4 still apply.

## License
GNU Affero General Public License v3.0 or later. Contributions need a one-time [CLA](https://github.com/soma-intelligence/onepass/blob/main/CLA.md).
```

---

## 3. Owner checklist

Run from a clone of the public repository with `soma-intelligence/onepass` as `origin`, or from this
worktree with the `public` remote (its push URL is disabled on purpose: set it first with
`git remote set-url --push public https://github.com/soma-intelligence/onepass.git`). The commands
below assume the remote is `public`. Each step is the owner's call; stop at any red step.

1. **Check the branch.** Three commits on top of `public/main` (8661a566), signed with the Soma Labs
   key and authored by Soma Labs like earlier exports: the squashed fix
   (`fix(devices): lock a device the list marks revoked, never erase it`), the version bump
   (`OnePass v0.2.1`), then this file. This file holds the owner checklist and the advisory before
   publication: keep it off the public push (steps 4 and 6 push `release/advisory-fix~1`), and add
   it after the advisory is published if wanted.

   ```sh
   git fetch public
   git log --format='%h %G? %an %s' public/main..release/advisory-fix
   git diff --stat public/main release/advisory-fix
   ```

2. **Run the gates.** Green locally on 2026-10-30: fmt, clippy `-D warnings`, `onepass-core` 692
   tests (848 with `dev-fast-kdf`, `signed_lists` included), VaultKit 378 tests (21 timed out under
   the parallel run on a loaded machine, all 21 pass with `--no-parallel`). Not run locally: the
   full workspace and the extension tests (only the version line changed there).

   ```sh
   (cd core && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings)
   (cd core && cargo test -p onepass-core --features dev-fast-kdf)
   (cd core && cargo test --workspace)   # about 25 min
   (cd extension && npm ci && npm test)
   apple/scripts/build-core.sh test
   (cd apple && ONEPASS_FFI_XCFRAMEWORK=../build/test/OnePassFFI.xcframework swift test --package-path VaultKit)
   ```

3. **Fill the placeholders** in this file (credit, release date). They only feed steps 9 and 10.

4. **Push the branch** (a private fork of the advisory is an alternative, see the note at the end).

   ```sh
   git push public release/advisory-fix~1:refs/heads/release/advisory-fix
   ```

5. **Open the PR** and wait for CI (`core`, `extension`, `cla`, `pinned-actions`).

   ```sh
   gh pr create -R soma-intelligence/onepass --base main --head release/advisory-fix \
     --title "fix(devices): lock a device the list marks revoked, never erase it" \
     --body "A device the signed device list marks revoked is locked, never erased; only the user erases it. Release v0.2.1."
   gh pr checks --watch -R soma-intelligence/onepass release/advisory-fix
   ```

6. **Land the commits on `main` as they are.** Earlier exports were pushed as commits signed by
   Soma Labs; a GitHub rebase or squash merge would re-commit them unsigned. Once CI is green,
   fast-forward `main` to the branch (GitHub then marks the PR merged):

   ```sh
   git push public release/advisory-fix~1:main
   git fetch public && git log --format='%h %G? %s' -3 public/main
   ```

   If branch protection refuses the push, use `gh pr merge --rebase` and accept unsigned commits,
   or allow the push for this release.

7. **Tag** the merged head with a signed, annotated tag, the same form as v0.1.4.

   ```sh
   git tag -s v0.2.1 -m "OnePass v0.2.1" public/main
   git tag -v v0.2.1
   git push public v0.2.1
   ```

8. **Build the release files** from the tag with the same private procedure as v0.1.4 (Mac app
   signed with Developer ID and notarized, Chrome zip), then the checksums.

   ```sh
   shasum -a 256 OnePass-0.2.1-mac.zip OnePass-0.2.1-chrome.zip > SHA256SUMS
   ```

9. **Create the release** as a pre-release, body from section 2.

   ```sh
   gh release create v0.2.1 -R soma-intelligence/onepass --verify-tag --prerelease \
     --title "OnePass v0.2.1" --notes-file release-notes-v0.2.1.md \
     OnePass-0.2.1-mac.zip OnePass-0.2.1-chrome.zip SHA256SUMS
   ```

10. **Update the draft advisory** with the final text (section 1), the ranges and the credit. In the
    web UI (Security, Advisories, GHSA-8wp4-pjw5-pppg, Edit), or:

    ```sh
    jq -n --rawfile body advisory-body.md '{
      summary: "A revoked device can make the device that revoked it erase its local vault",
      description: $body,
      severity: "medium",
      cwe_ids: ["CWE-285"],
      vulnerabilities: [{
        package: {ecosystem: "other", name: "onepass"},
        vulnerable_version_range: ">= 0.2.0, < 0.2.1",
        patched_versions: "0.2.1"
      }]
    }' > advisory.json
    gh api -X PATCH repos/soma-intelligence/onepass/security-advisories/GHSA-8wp4-pjw5-pppg --input advisory.json
    ```

    (`advisory-body.md` = section 1 from "Summary" to the end of "Timeline". Add credits in the UI.)

11. **Request a CVE** from GitHub, then publish.

    ```sh
    gh api -X POST repos/soma-intelligence/onepass/security-advisories/GHSA-8wp4-pjw5-pppg/cve
    gh api -X PATCH repos/soma-intelligence/onepass/security-advisories/GHSA-8wp4-pjw5-pppg -f state=published
    ```

    GitHub reviews the CVE request; publishing can wait for the CVE id or go first (the CVE is then
    added to the published advisory).

12. **Private repository.** Version 0.2.1 only exists on the public export; bump `onepass-dev`
    to match when its next export is cut, so the next public version is above 0.2.1.

**Note on a private fork.** GitHub lets an advisory carry a temporary private fork, so the fix can be
reviewed and tested before anything is public. Since 0.2.0 was never tagged and only people building
`main` are affected, pushing the branch directly (step 4) reveals the issue for the short time until
the advisory is published; use the private fork instead if that window matters.
