# DesignBridgeKit

The behaviour primitives every DesignBridge app shares (SPEC section 2, phase 2). Each one exists once, so every app behaves the same way. There is no branding here: each primitive takes its look from a `DBTheme` that the app fills from its generated tokens.

- Platforms: iOS 26, macOS 26, watchOS 26, visionOS 26 (glass falls back to materials on visionOS; the pasteboard is a no-op on watchOS). Swift 6.2 tools, Swift 6 language mode.
- No dependencies.
- Rule IDs refer to `research/ux-rulebook.md`.

```swift
.package(path: "../design-bridge/Packages/DesignBridgeKit")
```

```swift
WindowGroup {
    RootView()
        .dbToastHost()
        .dbTheme(DBStandardTheme(accent: Tokens.accent, sheetCornerRadius: Tokens.Radius.sheet))
        .dbLaunchOverrides()
}
```

The kit's own words (Retry, Undo, Copied, Dismiss, the loading and error copy) are localised in English, French, Spanish and Italian (`DBStrings`, `Resources/Localizable.xcstrings`).

## Launch overrides

`.dbLaunchOverrides()` is the app side of the DesignBridgeTesting launch contract. In Debug it reads `-DBColorScheme light|dark|system`, `-DBDynamicTypeSize <size>` and `-DBReduceMotion YES|NO`, or the environment variables `DB_THEME`, `DB_CONTENT_SIZE` and `DB_REDUCE_MOTION`. An argument wins over the variable. When `-UIPreferredContentSizeCategoryName` is also passed, the text size is left to UIKit, so the accessibility audit can still change it. Release builds ignore all of them. `DBLaunchOverrides.parse(arguments:environment:)` is the pure parser.

Under a DesignBridge UI test (`DB_UI_TESTING=1`, Debug only) toasts stay 3x longer (`DBToastTiming.uiTestingScale`), so a slow XCUITest snapshot still finds a 1.8 s confirmation.

## Registry

`PenpotComponent` and `protocol PenpotMapped` declare which Penpot main component a SwiftUI view draws, and how its props map (`text`, `swap`, `fill`, `variant`). `dbridge registry scan` and `dbridge drift` read these declarations.

## Theme

| API | Notes |
|---|---|
| `protocol DBTheme` | `accent`, `success`, `warning`, `error`, `info`, `textPrimary`, `textSecondary`, `sheetBackground`, `skeleton`, `sheetCornerRadius`, `spacing`, `toastFont`. Every requirement has a default. |
| `DBStandardTheme(...)` | Stored values with defaults, for generated tokens. |
| `DBSpacing` | 4, 8, 12, 16, 24, 32 by default (UX-SPACE-01). |
| `.dbTheme(_:)`, `@Environment(\.dbTheme)` | Injection and reading. |

## 1. DBToast

```swift
@Environment(\.toast) private var toast

toast(.success("Saved"))
toast(.info("Sync paused"))
toast(.undo("Item deleted") { restore() })
toast(.error("Couldn't save. Check your connection.", action: DBToastButton("Retry") { save() }))
toast.copyToClipboard(iban, label: "IBAN copied")
```

| API | Notes |
|---|---|
| `.dbToastHost()` | Once at the root. Injects `\.toast` and shows a Liquid Glass capsule at the top. Its container has the identifier `db.toast` (`DBToast.accessibilityIdentifier`). |
| `DBToast.success/info/error/undo` | Factories. `DBToast(kind:message:systemImage:action:duration:)` for the rest. |
| `DBToastPresenter.copyToClipboard(_:label:)` | Writes the pasteboard (UIKit or AppKit) and shows a success toast. |
| `DBToastTiming` | Success 1.8 s (1.5 to 2), info 2.5 s (1.5 to 4), with an action 5 s (4 to 6), error 6 s minimum. |
| `DBToastQueue` | Pure state machine: one visible, up to 3 waiting, duplicates coalesce, errors wait ahead of others, pause and resume. |
| `DBToastCenter` | Drives the queue with real time, announces each new toast once. |

Behaviour: swipe up to dismiss, the timer pauses while the toast is touched or focused by VoiceOver, a "Dismiss" accessibility action, success and error haptics, and a crossfade under Reduce Motion. Without a host, `toast(...)` logs an error instead of failing silently.

Rules: UX-TOAST-01, UX-TOAST-02, UX-TOAST-03, UX-TOAST-04, UX-TOAST-05, UX-ACT-05 (undo over confirm), UX-STATE-05 (errors are never silent), UX-GLASS-01.

## 2. DBNumber

```swift
DBNumber(steps)                                   // Int
DBNumber(score, format: .decimal(fractionDigits: 1))
DBNumber(balance, currencyCode: "EUR")
DBNumber(ratio, format: .percent())
Text(timer, format: .number).dbRollingNumber(value: Double(timer))
```

| API | Notes |
|---|---|
| `DBNumber` | `.contentTransition(.numericText(value:))`, `.monospacedDigit()`, the shared `DBMotion.number` spring. Animates on its own. |
| `DBNumberFormat` | `.integer`, `.decimal(fractionDigits:)`, `.currency(code:fractionDigits:)`, `.percent(fractionDigits:)`. |
| `DBNumberFormatting.string(_:format:locale:)` | The pure formatter, using the view's `\.locale`. |
| `.dbRollingNumber(value:)` | The same transition on any `Text`. |

Rules: UX-NUM-01, UX-NUM-02, UX-NUM-03, UX-MOT-03.

## 3. DBMotion

| API | Notes |
|---|---|
| `DBSpring.snappy` / `.smooth` / `.bouncy` | 0.25 s bounce 0, 0.4 s bounce 0, 0.45 s bounce 0.25. |
| `spring.animation(reduceMotion:)` | The spring, or `DBMotion.crossfade` (0.2 s ease in out). |
| `withDBAnimation(_:reduceMotion:_:)` | `withAnimation` with the fallback. |
| `.dbAnimation(_:value:)`, `.dbTransition(edge:)` | Read Reduce Motion from the environment. |
| `.buttonStyle(.dbPress)` | Scale 0.97 with the snappy spring; dims instead under Reduce Motion. |
| `.dbZoomSource(id:in:)`, `.dbZoomDestination(sourceID:in:)` | `matchedTransitionSource` plus `.navigationTransition(.zoom)`. No-op on macOS. |

Rules: UX-MOT-01, UX-MOT-02, UX-MOT-03, UX-MOT-04, UX-PRESS-01, UX-PRESS-02, UX-NAV-01, UX-NAV-03.

## 4. DBHaptics

```swift
.dbHaptic(.selection, trigger: tab)
.dbHaptic(trigger: result) { _, new in new.isSuccess ? .success : .error }
```

| Event | Feedback |
|---|---|
| `selection` | `.selection` |
| `snap` | `.impact(weight: .light)` |
| `commit` | `.impact(weight: .medium)` |
| `success` | `.success` |
| `warning` | `.warning` |
| `error` | `.error` |
| `increase` / `decrease` | `.increase` / `.decrease` |
| `levelChange` | `.levelChange` |

Rules: UX-HAPT-01, UX-HAPT-02, UX-HAPT-03, UX-TOAST-05.

## 5. DBScrollHero

```swift
DBScrollHero(heroHeight: 320, parallax: 0.4) {
    Image(.cover).resizable().scaledToFill()
} header: {
    Text("Lisbon").font(.largeTitle.bold())
} content: {
    TripDetails()
}
```

`heroHeight: nil` sizes the hero to its measured header. `position:` takes a `ScrollPosition` binding (to start scrolled, or to scroll to a card). A fixed backdrop, with sheet content (rounded top, `theme.sheetCornerRadius`) that scrolls over it. The header stays pinned, then fades and scales to 0.9 as the sheet covers it (`onScrollGeometryChange`). The backdrop moves at 0.3 to 0.5x (clamped) and stretches on pull-down. Under Reduce Motion the backdrop holds still and the header only fades. `DBScrollHeroMetrics` holds the pure geometry.

Rules: UX-SCROLL-03, UX-MOT-03, UX-SPACE-04 (continuous corners).

## 6. DBStates

```swift
@State private var trips = DBLoadable<[Trip]>.initial

trips.beginLoading()
do { trips.succeed(try await api.trips()) } catch { trips.fail(error) }

DBLoadableView(trips,
    empty: DBEmptyState("No trips yet", systemImage: "airplane", actionTitle: "Plan a trip") { plan() },
    retry: { Task { await reload() } }
) { trips in
    TripList(trips)
} placeholder: {
    TripList(Trip.samples)   // redacted while loading
}
```

| API | Notes |
|---|---|
| `DBLoadable<T>` | `.loading(previous:)`, `.empty`, `.failed(DBLoadError, previous:)`, `.content(T)`. A reload keeps the previous content; a cancellation is not an error. |
| `DBLoadable.Phase` | `skeleton`, `refreshing`, `empty`, `failed`, `failedOverContent`, `content`. |
| `DBLoadError` | User copy in one place: `LocalizedError` text, `.offline` for network loss, `.generic` otherwise. |
| `DBLoadableView` | Switches on the phase. A failure over content keeps the content and shows an error toast with Retry. |
| `DBLoadingView`, `DBDelayedSpinner`, `DBSkeleton`, `.dbShimmer()` | Redacted placeholder, spinner after 400 ms, shimmer 0.4 to 0.7 over 1.4 s, still under Reduce Motion. |
| `DBEmptyView`, `DBErrorView` | `ContentUnavailableView` with one action, and with Retry. |

Rules: UX-STATE-01, UX-STATE-02, UX-STATE-03, UX-STATE-04, UX-STATE-05, UX-SCROLL-07.

## 7. DBGlass

| API | Notes |
|---|---|
| `.dbFloatingGlass(_:in:interactive:tint:)` | `glassEffect` for floating controls only. `.regular` by default, `.clearOverMedia` over photos, maps and video. |
| `DBGlassGroup(spacing:)` | `GlassEffectContainer`, so nearby glass blends instead of stacking. |
| `.dbPrimaryAction()` / `.dbSecondaryAction()` | `.buttonStyle(.glassProminent)` once per screen, `.buttonStyle(.glass)` for the rest. |

The do's and don'ts are in the comments of `DBGlass.swift`: glass never on content and never stacked, no custom bar backgrounds, and the native `TabView` with `Tab(role: .search)` as the only search entry.

Rules: UX-GLASS-01 to UX-GLASS-08, UX-ACT-01.

## 8. DBText

```swift
Text(name).dbText(maxLines: 2)                       // wrap, then scale to 0.85
Text("Transfer to savings").dbText(maxLines: 1) {    // then fall back
    Text("Transfer").dbText()
}
DBAdaptiveStack { Text("Balance"); Spacer(); DBNumber(balance, currencyCode: "EUR") }
Text(title).dbTruncationProbe("detail.title")        // debug only
RootView().dbTruncationLogging()
```

| API | Notes |
|---|---|
| `.dbText(maxLines:minimumScale:)` | Wraps up to `maxLines`, then scales down to `minimumScale` (never below 0.7). Without `maxLines` it wraps freely. |
| `.dbText(maxLines:minimumScale:fallback:)` | `ViewThatFits` that keeps the wrapped and scaled text while it fits, then the fallback. |
| `DBAdaptiveStack` | Row, or column when the row does not fit or at accessibility sizes. |
| `.dbTruncationProbe(_:)` | Debug only. Compares the actual size with hidden ideal-size copies, outlines truncated text in red, and publishes `DBTruncationReport` through `DBTruncationPreferenceKey`. |
| `.dbTruncationMonitor(_:)`, `.dbTruncationLogging()` | Receive or log the reports (subsystem `DesignBridgeKit`, category `Truncation`). |

Rules: UX-TEXT-01, UX-TEXT-02, UX-DT-01.

## Catalogue

`DBCatalogueView` shows every primitive and has `#Preview`s (default, dark at AX3, themed, scroll hero, states, zoom). Apps can also put it in a debug menu:

```swift
NavigationStack { DBCatalogueView() }.dbToastHost()
```

## Tests

```sh
swift test
xcodebuild test -scheme DesignBridgeKit -destination 'platform=iOS Simulator,name=<device>'
```

Swift Testing suites cover toast timing and the queue, the toast center and copy helper, number formatting in en_US, fr_FR and de_DE, the loadable state machine and error copy, spring tokens, the haptics map, scroll hero geometry, the text fit budget, the truncation check, and theme defaults.

`SensoryFeedback` equality cannot tell impact weights apart in the iOS 26 and macOS 26 SDKs, so the `snap` and `commit` weights are not checked by a test.
