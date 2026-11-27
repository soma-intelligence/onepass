# README hero, proposed snippet

Copy `readme-hero.png` to `docs/assets/readme/hero-devices.png`, then put this right under the title
of `README.md` (not applied, README.md untouched):

```markdown
<p align="center">
  <img src="docs/assets/readme/hero-devices.png" width="100%"
       alt="OnePass on Mac, iPad, iPhone and Apple Watch, showing a fictional demo vault">
</p>

<p align="center">
  An open source password manager for your Apple devices.<br>
  End to end encrypted, kept on your device and in your private iCloud.
</p>
```

Every screen in the image is a real capture of the 1.0.1 build (store-0.3.0) with the Debug demo
vault (fictional data, Camille Durand). Only the wall behind them is generated.

# App Store sets

| Folder | Size | Slides |
| --- | --- | --- |
| `iphone-6.9/` | 1320 x 2868 | 6 |
| `iphone-6.3/` | 1206 x 2622 | 6 |
| `ipad-13/` | 2064 x 2752 | 4 |
| `mac/` | 2880 x 1800 | 4 |
| `watch-ultra/` | 422 x 514 | 1 (raw capture) |

Headlines (subline under each):

1. Every password, one calm place. Logins, cards and passkeys on every Apple device.
2. Sign in without the hunt. Passwords and one-time codes fill in Safari and apps. (iPhone only)
3. See what needs a fix. Watchtower flags weak and reused passwords.
4. Tidy up duplicates. See what differs, then merge in one go.
5. Yours alone, end to end. Encrypted on your device (Mac) and in your private iCloud.
6. Open source, top to bottom. Read every line of the code that guards your vault. (iPhone only)

Rebuild: `sources/tools/compose.py` (slides), `sources/tools/hero.py` (hero), copy in
`sources/tools/slides.py`. Captures in `sources/shots/`, generated backgrounds in `sources/ai/`.
