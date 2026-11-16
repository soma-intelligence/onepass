# Site setup maps

One file per site, named `<domain>.json`, read by `scripts/site_pack.py build --setup data/site-setup`.
These are the only hand-written inputs of the signed site pack. Everything else (which sites
offer 2FA and passkeys) comes from the 2FA Directory and 2factorauth/passkeys checkouts.

## File shape

```json
{
  "domain": "github.com",
  "additional_domains": ["githubassets.com"],
  "setup_totp": {
    "url": "https://github.com/settings/security",
    "verified": { "date": "2026-11-20", "browser": "chromium" },
    "steps": []
  },
  "setup_passkey": { "url": "...", "verified": { "date": "...", "browser": "..." }, "steps": [] }
}
```

`additional_domains`, `setup_totp` and `setup_passkey` are optional. `steps` may be empty: the
pack then only carries the settings page URL. `browser` is `chromium`, `firefox` or `safari`.
`url` follows the same rule as a `goto`.

## Verified or left out

A block without `verified` stays out of the pack and is listed in `report.json` under
`refused`. The owner sets `verified` (date and browser) only after walking the recipe on his
own signed-in account in that browser. Nobody else, and no script, sets it.

## Recipe rules

The build and the app (at load) enforce the same rules. A broken recipe fails the build and
names the file and the rule.

| Rule | Detail |
|---|---|
| Vocabulary | `goto`, `click`, `wait_for`, `reauth`, `expect_qr`, `expect_passkey_prompt`, `done`. Unknown `do` or key is refused. |
| `goto` | `url` is https, on the site's domain or a subdomain, or on one of its additional domains. No credentials, no port. |
| `click`, `wait_for` | `role` is `button`, `link`, `radio`, `checkbox`, `tab`, `menuitem` or `option`; `name` is a non-empty list of 1 to 80 character strings; optional `css` of at most 200 characters. |
| No text entry, no script | There is no `type` step and no way to run code. |
| Length | At most 12 steps. |
| Timeout | `timeout_s` is an integer from 1 to 60, optional on every step. |
| Destructive click | A `click` name containing, as a whole word, delete, disable, remove, pay or their French, Spanish and Italian forms is refused. |
| Final click | A `click` name equal to verify, activate, confirm, submit or their translations is refused. |
| Ending | A `setup_totp` recipe ends with `expect_qr` and never contains `expect_passkey_prompt`; a `setup_passkey` recipe ends with `expect_passkey_prompt` and never contains `expect_qr`. |

Additional domains: a site's own domain is never another site's additional domain, and a
domain several sites claim goes to the first of them in sorted order. An additional domain that is a public suffix is dropped.

The same recipe fixtures serve the Python build and the Rust core:
`core/onepass-core/tests/fixtures/site-pack/recipes/{valid,invalid}`.
