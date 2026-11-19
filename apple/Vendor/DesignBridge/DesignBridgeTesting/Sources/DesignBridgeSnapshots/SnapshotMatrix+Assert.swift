#if canImport(UIKit) && os(iOS)
import SnapshotTesting
import SwiftUI
import UIKit

extension SnapshotDevice {
    /// The device frame as a swift-snapshot-testing `ViewImageConfig`.
    @MainActor public var viewImageConfig: ViewImageConfig {
        ViewImageConfig(
            safeArea: UIEdgeInsets(top: safeArea.top, left: safeArea.left, bottom: safeArea.bottom, right: safeArea.right),
            size: size,
            traits: traits
        )
    }

    @MainActor public var traits: UITraitCollection {
        UITraitCollection { t in
            t.userInterfaceIdiom = idiom == .phone ? .phone : .pad
            t.horizontalSizeClass = horizontalSizeClass == .compact ? .compact : .regular
            t.verticalSizeClass = verticalSizeClass == .compact ? .compact : .regular
            t.displayScale = scale
            t.layoutDirection = .leftToRight
            t.forceTouchCapability = .unavailable
        }
    }
}

extension SnapshotContentSize {
    public var uiContentSizeCategory: UIContentSizeCategory {
        switch self {
        case .xSmall: .extraSmall
        case .large: .large
        case .accessibility3: .accessibilityExtraLarge
        case .accessibility5: .accessibilityExtraExtraExtraLarge
        }
    }
}

extension SnapshotVariant {
    /// Traits layered over the device traits: appearance and content size.
    @MainActor public var traits: UITraitCollection {
        UITraitCollection { t in
            t.userInterfaceStyle = appearance == .light ? .light : .dark
            t.preferredContentSizeCategory = contentSize.uiContentSizeCategory
        }
    }
}

/// Snapshots `view` across `matrix` (by default light/dark x xSmall, large, AX3, AX5 x iPhone 17
/// Pro, Pro Max, foldable unfolded, iPad x en, fr, pseudo). Each image is named
/// `<name>.<device>-<appearance>-<size>-<locale>`.
///
/// The same view is used for every locale; locale and Dynamic Type reach it through the
/// environment. Use the closure overload when strings must change per locale (fixtures, pseudo).
///
/// Call from a `@MainActor` Swift Testing test. Record with the `.snapshots(record: .missing)`
/// trait locally and `.never` on CI, or pass `record:`.
@MainActor
public func snapshotMatrix<V: View>(
    of view: V,
    name: String,
    matrix: SnapshotMatrix = .standard,
    precision: Float = SnapshotMatrixDefaults.precision,
    perceptualPrecision: Float = SnapshotMatrixDefaults.perceptualPrecision,
    record: SnapshotTestingConfiguration.Record? = nil,
    fileID: StaticString = #fileID,
    file filePath: StaticString = #filePath,
    testName: String = #function,
    line: UInt = #line,
    column: UInt = #column
) {
    snapshotMatrix(
        of: { _ in view },
        name: name,
        matrix: matrix,
        precision: precision,
        perceptualPrecision: perceptualPrecision,
        record: record,
        fileID: fileID,
        file: filePath,
        testName: testName,
        line: line,
        column: column
    )
}

/// Snapshots the view built for each variant. The closure receives the variant, so it can read
/// `variant.locale.text("Fixture")` or `variant.locale.string("key", bundle: .module)`.
@MainActor
public func snapshotMatrix<V: View>(
    of content: (SnapshotVariant) -> V,
    name: String,
    matrix: SnapshotMatrix = .standard,
    precision: Float = SnapshotMatrixDefaults.precision,
    perceptualPrecision: Float = SnapshotMatrixDefaults.perceptualPrecision,
    record: SnapshotTestingConfiguration.Record? = nil,
    fileID: StaticString = #fileID,
    file filePath: StaticString = #filePath,
    testName: String = #function,
    line: UInt = #line,
    column: UInt = #column
) {
    for variant in matrix.variants {
        let view = content(variant).snapshotEnvironment(variant)
        assertSnapshot(
            of: view,
            as: .image(
                precision: precision,
                perceptualPrecision: perceptualPrecision,
                layout: .device(config: variant.device.viewImageConfig),
                traits: variant.traits
            ),
            named: "\(name).\(variant.name)",
            record: record,
            fileID: fileID,
            file: filePath,
            testName: testName,
            line: line,
            column: column
        )
    }
}
#endif
