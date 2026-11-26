# DesignBridgeTesting

Test-side half of DesignBridge (SPEC phase 4). Four pieces:

| Product | What it does | Runs on |
|---|---|---|
| `DesignBridgeSnapshots` | `snapshotMatrix(of:name:)` on swift-snapshot-testing 1.19.x, plus the locale model and the pseudo-locale | Matrix model: anywhere. Rendering: iOS |
| `DesignBridgeUITesting` | `DBUITestCase`, the XCUITest base class with the accessibility audit and the screen rules | iOS UI test targets |
| `DBDiff` | SSIM with an offset tolerance, diff heat maps, the HTML report | macOS and iOS |
| `dbdiff` | Command line front end of `DBDiff` | macOS |

Swift 6.2 tools, iOS 17 and macOS 14 minimum (`performAccessibilityAudit` needs iOS 17).

```swift
.package(path: "../design-bridge/Packages/DesignBridgeTesting")
// snapshot test target
.product(name: "DesignBridgeSnapshots", package: "DesignBridgeTesting")
// UI test target
.product(name: "DesignBridgeUITesting", package: "DesignBridgeTesting")
```

## 1. Snapshot matrix

```swift
import DesignBridgeSnapshots
import Testing

@MainActor
@Suite(.snapshots(record: .missing))   // use .never on CI
struct MenuRowSnapshots {
    @Test func menuRow() {
        snapshotMatrix(of: RXMenuRow(title: "Face ID", accessory: .toggle), name: "menu-row")
    }

    // When strings change per locale, build the view per cell.
    @Test func settings() {
        snapshotMatrix(of: { variant in
            SettingsView(title: variant.locale.string("settings.title", bundle: .main))
        }, name: "settings", matrix: .smoke)
    }
}
```

- **Axes of `.standard`:** 96 images per view.
  - Light and dark.
  - Content sizes `xSmall`, `large`, `accessibility3` and `accessibility5`.
  - Devices: iPhone 17 Pro (402 x 874), iPhone 17 Pro Max (440 x 956), the foldable unfolded (iPhone Duo inner screen, 669 x 951, regular width) and iPad 11-inch (834 x 1210 @2x).
  - Locales `en`, `fr` and `pseudo`.
- **Narrower sets:** narrow with `.with(devices:)`, `.with(locales:)` and the others, or use `.smoke` (8 images: iPhone 17 Pro, light/dark, large/AX5, en/pseudo).
- **Precision:** 0.99, perceptual precision 0.98 (`SnapshotMatrixDefaults`).
- **Names:** `<test>.<name>.<device>-<appearance>-<size>-<locale>.png`, for example `menuRow.menu-row.iPhone17Pro-dark-ax5-fr.png`.
- **Environment:** each cell sets `locale`, `dynamicTypeSize` and `colorScheme` in the SwiftUI environment. It also sets the matching UIKit traits (style, content size, idiom, size classes, scale), so UIKit-backed chrome follows.
- **Pseudo-locale** (`SnapshotLocale.pseudo`, tag `en_XA`):
  - accents every letter, wraps the string in `[...]` and pads it by about 40%;
  - keeps `%@`, `%1$d`, `%.2f`, `%%` and `{name}` intact;
  - a missing closing `]` in a snapshot means the label was clipped.
  - `variant.locale.text(_:)` applies it to fixture strings. `variant.locale.string(_:table:bundle:)` reads the `.lproj` table (String Catalogs compile to one), then applies it.
- **Foldable safe area:** the safe area of the foldable frame is an estimate. Replace it with values read from the simulator once someone measures it.

Rendering needs the iOS simulator: `xcodebuild test -destination 'platform=iOS Simulator,...'`. `swift test` on macOS runs only the model tests. The package's own render test (`SnapshotMatrixRenderTests`) keeps its references in `Tests/DesignBridgeSnapshotsTests/__Snapshots__`. They were recorded on an iPhone 17e simulator, iOS 27.2, with Xcode 27.2.

## 2. XCUITest base class

**Choice: an SPM library target that compiles conditionally.** Every XCTest file is wrapped in `#if canImport(XCTest) && os(iOS)`. On macOS the module builds empty, apart from `DBLaunchConfiguration`, which is platform neutral and unit tested. App UI test targets add the `DesignBridgeUITesting` product; there are no files to copy.

```swift
import DesignBridgeUITesting
import XCTest

final class VaultFlow: DBUITestCase {
    override var auditAllowlist: [DBAuditAllowance] {
        [.init(.contrast, identifier: "hero-illustration", reason: "decorative, hidden from VoiceOver in 1.1")]
    }

    func testCopyShowsToast() throws {
        launchApp()                                   // theme, size, motion from DB_* env or the override
        app.buttons["copy-password"].tap()
        assertToast("Copied", disappearsWithin: 3)
        assertNoDuplicateActions()
        assertReachable(lastElement: app.cells["row-last"])
        try assertNotTruncated()
        try assertAccessibilityAudit()
        saveScreenshot(named: "vault")                // for dbdiff, when DB_SCREENSHOT_DIR is set
    }
}
```

- **`launchApp()`** passes `DBLaunchConfiguration.launchArguments` and sets `XCUIDevice.shared.appearance`. The appearance is reset in `tearDown`.
  - The configuration comes from an override of `launchConfiguration`, from `configurationOverride`, or by default from the runner environment: `DB_THEME`, `DB_CONTENT_SIZE`, `DB_REDUCE_MOTION` and `DB_LOCALE`.
  - From `xcodebuild`, set them as `TEST_RUNNER_DB_THEME=dark` and so on.
- **`assertAccessibilityAudit(_:allowlist:)`** wraps `performAccessibilityAudit`.
  - An allowance always names an audit type plus an element identifier or label, and a reason. There are no global exclusions.
  - It lists every rejected issue in one failure. Accepted issues are attached to the result.
- **`assertNotTruncated()`** is the same audit limited to `.textClipped`.
- **`assertNoDuplicateActions(in:ignoring:)`** fails when two hittable on-screen buttons share a label or an identifier (UX-ACT-02).
- **`assertReachable(lastElement:in:bottomObstructions:)`** scrolls to the end. It then checks that the element is hittable and ends above the tab bar and any floating bottom control (UX-SAFE-02).
- **`assertToast(_:timeout:disappearsWithin:)`** checks UX-TOAST-01, 02 and 03:
  - waits for an element whose label contains the text, preferring one inside `toastIdentifier` (default `db.toast`);
  - fails if the toast overlaps the tab bar;
  - optionally checks that it goes away.

### App-side launch contract

The app (through DesignBridgeKit) should read these at launch:

| Argument | Values | System honours it |
|---|---|---|
| `-DBColorScheme` | `light`, `dark`, `system` | no: apply `.preferredColorScheme` |
| `-DBDynamicTypeSize` | `xSmall`, `large`, `accessibility3`, `accessibility5` | no, but `-UIPreferredContentSizeCategoryName` is also passed and is honoured |
| `-DBReduceMotion` | `YES`, `NO` | no: override `accessibilityReduceMotion`. `-UIAccessibilityReduceMotionEnabled` is passed too, but iOS may ignore it |
| `-AppleLanguages`, `-AppleLocale` | from `locale` | yes |
| `-NSDoubleLocalizedStrings` | `YES` when `doubleLengthStrings` is on | yes (doubles strings, not the 40% pseudo) |
| env `DB_UI_TESTING` | `1` | n/a |

`DBToast` sets `.accessibilityIdentifier("db.toast")` on its container; `assertToast` also falls back to matching any element by label. The app applies the arguments with `.dbLaunchOverrides()` (DesignBridgeKit); with `-UIPreferredContentSizeCategoryName` present it leaves the text size to UIKit. `DB_UI_TESTING=1` makes toasts stay 3x longer in Debug.

## 3. Visual diff: `dbdiff`

```sh
swift run -c release dbdiff design/exports screenshots --config designbridge.json --out parity-report
```

- **Inputs:** two PNG files, or two folders. Folders are paired by file name, ignoring case and the `@1x`, `@2x` and `@3x` suffixes, so `Settings@3x.png` pairs with `settings.png`. A missing side is reported as a failure.
- **Score:**
  - SSIM is computed on 8 x 8 windows with a stride of 4.
  - By default it is the mean of the R, G and B channels (`--color rgb`). Luma alone misses a blue button turned red of the same brightness. `--color luma` is the fast, colour-blind option.
  - Transparent Penpot exports are flattened over white.
- **Offset tolerance:**
  - every shift up to `maxOffsetPt * scale` pixels is tried on luma, and the best one is kept;
  - SSIM is recomputed on the overlap;
  - both the shifted and the unshifted SSIM are reported, so a pure offset problem is visible.
- **Thresholds:** read from `--config`, which takes `parity.json` or the `parity` key of `designbridge.json`. Flags override the file.

  ```json
  {"ssim": 0.97, "maxOffsetPt": 1, "scale": 3,
   "masks": [[0, 0, 402, 54]],
   "overrides": {"Settings": {"ssim": 0.95, "masks": [[0, 800, 402, 74]]}}}
  ```

  Masks are in points and are painted grey in both images. Use them for the status bar, clocks and avatars.
- **Size:** a candidate of a different size is resampled when the aspect ratio matches within 1%. Otherwise, or with `--no-resize`, the pair fails.
- **Output:**
  - `index.html`: one card per pair with SSIM, offset, changed pixel share and the three panels (Penpot, app, diff heat map: changes in red, outside the overlap in blue);
  - `report.json` for CI;
  - `images/`.
- **Exit codes:** 0 when everything passes, 1 when a pair fails or is missing, 2 on a usage or I/O error. `--report-only` always exits 0, for the report phase before a component becomes a gate.

Library use: `VisualDiff.run(reference:candidate:output:config:)`, or `ImageComparator.compare(reference:candidate:options:)` on `RGBAImage` values.

## 4. CI template

`../../ci/designbridge-app.yml` is a reusable `workflow_call` template for app repos. It is not wired into `.github` here.

- **Setup:** `macos-26` runners with Xcode pinned (`xcode-version` input, default `26.2`; check it against the runner image). SPM and DerivedData are cached on `Package.resolved`.
- **`tokens`:** `dbridge gen --check`, then `git diff --exit-code`.
- **`drift`:** `dbridge drift`, with its markdown added to the job summary.
- **`snapshots`:** `xcodebuild test` on a booted, status-bar-pinned simulator, with `SNAPSHOT_TESTING_RECORD=never`. Failure diffs are uploaded.
- **`ui-flows`:** only when `run-ui-flows` is true (nightly or on demand).
  - It runs a matrix of light/dark by large/AX5, passing `DB_THEME` and `DB_CONTENT_SIZE` to `DBUITestCase`.
  - It then runs `dbdiff --report-only` from the flow screenshots against `design/exports`.

The `dbridge` commands and the `soma-intelligence/design-bridge` clone URL are placeholders.

## Tests

```sh
swift build && swift test        # macOS: SSIM, offset, diff, report, config, pairing, pseudo-locale, matrix, launch contract
xcodebuild test -scheme DesignBridgeTesting-Package -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  -only-testing:DesignBridgeSnapshotsTests   # adds the iOS render test
```

## Not done yet

- **`TruncationProbe`:** truncation is covered by the audit's `.textClipped` check and by the pseudo-locale snapshots. `TruncationProbe` belongs in DesignBridgeKit, and `DBUITestCase` has no assertion on it yet.
- **UI test runs:** `DBUITestCase` compiles for iOS but has not run against a real app. The first consumer (Kelid RX) will be the real test.
- **Text weighting:** text is not masked or down-weighted in the visual diff. Use masks per board until Penpot and Core Text rasterise closer.
- **CI template:** not run on GitHub yet.
