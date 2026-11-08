# OnePass redesign: meaningful washes and a tighter system

Date: 2026-11-07. Status: approved in conversation, section by section; this document awaits review.

## Goal

OnePass looks generic, as if generated. The fix is not a new identity: the layout, the navigation,
the floating tab bar, the Lattice mark and the indigo accent (#5856D6) stay. The redesign adds taste
to what exists in two ways:

1. A few subtle gradients ("washes"), each carrying a meaning: a state, an identity or an action.
2. A tighter system of spacing, radii, text levels and depth, so every screen uses the same values.

Success: the iPhone Home, item detail, Watchtower and generator screens read as one deliberate
product in light, dark and Increase Contrast, and every other surface follows the same tokens.

Concept boards (Azure gpt-image-2.5, R1-dark and R2-light) set the direction. They are not pixel
references: the image model invented text and drew the strength bar wrong.

## What exists today

- The Watchtower arc already uses an `AngularGradient` red, orange, yellow, green
  (`apple/App/Browse/Pages/WatchtowerPage.swift`).
- `TotpRing` and `TotpCountdown` already blend from the accent to red over the last five seconds
  (`apple/DesignKit/Sources/DesignKit/TotpRing.swift`).
- About 20 views build their own gradient (`Theme.accent.gradient`, `color.gradient`, ad hoc
  `LinearGradient`), with no shared rule.
- The app uses 10 stack spacings (0, 1, 2, 4, 6, 8, 10, 12, 14, 16), 8 corner radii from 7 to 26,
  and `.secondary` 319 times against `.tertiary` 21 times.
- The Watch target does not import DesignKit.
- The browser extension has its own tokens in `extension/src/ui/theme.css`.

## Section 1: wash tokens

A new namespace `Theme.Wash` in DesignKit holds five named gradients. No view builds a gradient by
hand after the redesign; a view picks a wash by its meaning.

| Token | Meaning | Look | Used by |
|---|---|---|---|
| `Wash.scale(fraction:)` | How good a score is | Red, amber, green along the scale, clipped at the current value; the rest is the neutral track | Watchtower arc, `StrengthMeter`, `StrengthBadge` |
| `Wash.alert(_ color:)` | A state that asks for an action | Top to bottom: the color mixed 8% with white, to the color mixed 6% with black | Exposed card, crypto phrase alert, `IntegrityBanner` |
| `Wash.identity(_ color:)` | Whose item this is | The item icon's color at 14% opacity (light) or 22% (dark), fading to 0 at 30% of the screen height | Item detail header |
| `Wash.accent` | The primary action, the account | Vertical, `accent.mix(with: .white, by: 0.10)` to `accent` | Primary buttons, account avatar, pairing tiles |
| `Wash.countdown(remaining:)` | Time left on a code | The existing TOTP blend, moved into Theme without a visual change | `TotpRing`, `TotpCountdown` |

Rules:

- `scale` clipping: in `StrengthMeter`, each lit segment takes the color of its own position on
  the scale. Four lit segments of four read green, never a rainbow. In the arc, the gradient is
  mapped to the full arc and masked by the filled part.
- `identity` fallback: when the icon color is black, white or gray (saturation under 0.15), the wash
  uses the accent instead, so a GitHub item gets indigo, not nothing.
- `accent` replaces every `Theme.accent.gradient` call.
- Calm cards stay flat. Dark cards stay on the system gray (`Theme.card`); no indigo tint.

Banned everywhere: glow, mesh gradients, glass tints on cards, gradients on text, and any gradient
that carries no state, identity or action.

Accessibility:

- Any text over a wash keeps 4.5:1 contrast or better.
- Increase Contrast and Reduce Transparency replace every wash with its flat base color.

## Section 2: refinement rules

### Spacing: `Theme.Space`

One 4 pt scale: `xxs 2`, `xs 4`, `s 8`, `m 12`, `l 16`, `xl 24`, `xxl 32`.

- Values 1, 6, 10 and 14 go: each one rounds to the nearest step, then the screen is checked by eye.
- Screen gutter: 16 on iPhone, 20 on iPad.
- Inside a card: 12. Between sections: 24.

### Radius: `Theme.Radius`

Four values, all `.continuous`: `chip 8` (glyphs, small tiles), `control 12` (buttons, fields),
`card 18` (the current `cardRadius`), `sheet 26`. A nested shape uses the outer radius minus the
padding between them, so corners stay concentric.

### Text levels

- `.primary`: titles and values.
- `.secondary`: labels and subtitles.
- `.tertiary`: metadata (dates, counts, last used).
- Numbers (scores, counts, TOTP) use `.monospacedDigit()`. The rounded design is for hero numbers
  only: the Watchtower score and the Home counts.
- No weight lighter than `.regular`. At most one `.semibold` per row.

### Depth and hairlines

- Dark: cards have no shadow.
- Light: cards have one soft shadow, black at 4%, radius 12, y offset 4.
- Rows inside a card are separated by inset hairlines that start at the text, not at the card edge.
- `Theme.cardHairline` stays.

### Icons

- Site icons sit on a fixed tile: `chip` radius, 36 pt in lists, 56 pt in the detail header, with a
  1 px `cardHairline` border so black or white logos never bleed into the card.
- SF Symbols use hierarchical rendering and one weight per screen.

### Motion

- `Motion` keeps its `.snappy` and `.smooth` curves.
- A wash fades in once (0.25 s) the first time its view appears. Nothing loops.
- With Reduce Motion, no fade.

### Out of scope

Copy, layout, navigation and the tab bar do not change. The Lattice mark and #5856D6 stay.

## Section 3: surfaces

1. **iPhone** (the reference, built first).
   - Home: `alert` on Exposed and the crypto alert, `scale` on the counts row.
   - Item detail: `identity` behind the header, `StrengthBadge` on `scale`.
   - Watchtower: the arc moves to `Wash.scale`.
   - Generator: `StrengthMeter` on `scale`.
   - The spacing, radius and text sweep runs here first.
2. **iPad**: the same views. The 20 pt gutter. `identity` covers the detail column only, never the
   sidebar.
3. **Mac**: the window glass stays. Washes appear inside detail panes only (`identity` in the item
   pane, `alert` on Watchtower rows), never on the sidebar or the list. The elliptical gradients in
   `apple/App/Browse/Mac/NewItemMenu.swift` are checked against the banned list and become flat
   unless they carry a meaning.
4. **Watch**: the Watch target links DesignKit for the tokens only. It uses `countdown` and a thin
   `identity` band at the top of the entry detail. Nothing else.
5. **visionOS**: washes sit on glass at half opacity. `identity` is not used (the window material
   tints itself). `alert` and `scale` stay.
6. **Browser extension**: `extension/src/ui/theme.css` gets CSS variables that mirror the washes
   (`--wash-scale`, `--wash-alert`, `--wash-identity`, `--wash-accent`). The `--r-*` radii and the
   spacing map to the same numbers as `Theme.Radius` and `Theme.Space`. The same banned list applies.

## Build order

1. DesignKit tokens (`Theme.Wash`, `Theme.Space`, `Theme.Radius`) and their tests.
2. iPhone screens.
3. iPad.
4. Mac.
5. Watch and visionOS.
6. Browser extension.

## Testing

- Unit tests for the tokens that carry logic: `scale` clipping and segment colors, the `identity`
  fallback for low saturation colors, the Increase Contrast and Reduce Transparency fallbacks.
- Before and after snapshots of every touched screen in light, dark and Increase Contrast, on
  simulators, with fictional data only.
- The existing test suites stay green.

## Delivery

- Work happens on OnePass `main` in the main checkout. No worktree.
- Commits stay local. Nothing is pushed or merged without the owner's yes.
