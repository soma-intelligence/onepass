# Frosted Réglages, shared across apps (2026-11-17)

## Goal

One Réglages look for OnePass, Prism and Soma Flight, after the owner's reference screenshot:
translucent frosted cards over a heavily blurred wallpaper. The shared part gives the structure
and the style. Each app supplies only its rows, an optional plan card and its footer lines.

## Look

- Background: the app's wallpaper, blurred hard and dimmed (dark) or lightened (light), filling
  the whole screen. No photo band, no opaque page sheet. Everything scrolls together over it.
- Top: the system close button (glass) on the leading side. A large centred avatar, the name big
  and bold, a detail line under it (OnePass: the device mode) with an optional small glyph.
- On scroll the name goes under a soft blur at the top and a small avatar appears centred in the
  bar.
- Cards: frosted translucent fills (not Liquid Glass), continuous corners of 28 pt. Liquid Glass
  stays on the bar and controls only.
- Plan card (optional): title, subtitle, a row of perk discs, the metal card art off the trailing
  edge, on a frosted panel.
- Rows: monochrome glyph (white in dark, black in light) without a coloured tile, title, optional
  subtitle, optional count badge (white capsule, dark digits). No chevron, no separators, 60 pt
  pitch.
- Last card on its own: the sign-out action (OnePass: Verrouiller).
- Footer: small centred tertiary lines (name and version, publisher, last activity).
- Removed: the "Get more from Plus" carousel on the root.
- Sub-pages: the same blurred background and frosted rows.
- Reduce Transparency and Increase Contrast: opaque card fill and the plain page colour.

## Shared component (DesignKit, `RXFrosted.swift`)

- `RXFrostedBackdrop(image:)`: the blurred, tinted wallpaper.
- `RXFrostedPage(backdrop:compact:header:content:)`: the scroll, the backdrop, the top blur and
  the compact header in the bar once the large header has scrolled away.
- `RXFrostedProfileHeader(avatar:name:detail:detailSymbol:)`.
- `RXFrostedCard { }`, `RXFrostedRow(title, systemImage:, subtitle:, badge:, tint:)`.
- `RXFrostedFooter(lines:)`.
- `PlanCard(..., frosted: true)`: the existing card on a frosted panel.
- `.rxFrostedForm()` for the Form sub-pages: hidden list background and frosted row fills.

Prism (SomaUI) and Soma Flight copy the same component in a later step; this step ships OnePass.

## Plan

1. Add `RXFrosted.swift` to DesignKit and the `frosted` panel to `PlanCard`.
2. Rebuild `RXSettingsHome` on it, wallpaper from `RXWallpaper`, carousel removed.
3. Sub-pages: `settingsPage` uses the frosted backdrop and rows when the RX look is on.
4. Build iOS, run the RX UI tests, capture light and dark on the simulator.
5. Commit, install on the iPhone.
