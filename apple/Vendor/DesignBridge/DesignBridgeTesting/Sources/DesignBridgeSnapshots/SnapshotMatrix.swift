import CoreGraphics
import Foundation
import SwiftUI

// The matrix model is platform neutral so it can be unit tested on macOS. The assertion that
// renders it lives in SnapshotMatrix+Assert.swift and needs UIKit.

/// Default comparison precision for the matrix. Perceptual 0.98 absorbs anti-aliasing changes
/// across Xcode minor versions without hiding real layout changes.
public enum SnapshotMatrixDefaults {
    public static let precision: Float = 0.99
    public static let perceptualPrecision: Float = 0.98
}

public enum SnapshotAppearance: String, CaseIterable, Sendable, Hashable {
    case light
    case dark

    public var colorScheme: ColorScheme { self == .light ? .light : .dark }
}

/// Dynamic Type sizes in the matrix: the smallest, the default and two accessibility sizes.
public enum SnapshotContentSize: String, CaseIterable, Sendable, Hashable {
    case xSmall
    case large
    case accessibility3
    case accessibility5

    public var dynamicTypeSize: DynamicTypeSize {
        switch self {
        case .xSmall: .xSmall
        case .large: .large
        case .accessibility3: .accessibility3
        case .accessibility5: .accessibility5
        }
    }

    /// Short form used in snapshot file names.
    public var shortName: String {
        switch self {
        case .xSmall: "xs"
        case .large: "l"
        case .accessibility3: "ax3"
        case .accessibility5: "ax5"
        }
    }
}

/// A device frame: logical size in points, safe area, scale and size classes.
public struct SnapshotDevice: Sendable, Hashable {
    public enum Idiom: String, Sendable, Hashable { case phone, pad }
    public enum SizeClass: String, Sendable, Hashable { case compact, regular }

    public struct Insets: Sendable, Hashable {
        public var top: CGFloat, left: CGFloat, bottom: CGFloat, right: CGFloat
        public init(top: CGFloat, left: CGFloat = 0, bottom: CGFloat, right: CGFloat = 0) {
            self.top = top
            self.left = left
            self.bottom = bottom
            self.right = right
        }
    }

    /// Stable identifier used in snapshot file names.
    public var id: String
    public var size: CGSize
    public var safeArea: Insets
    public var scale: CGFloat
    public var idiom: Idiom
    public var horizontalSizeClass: SizeClass
    public var verticalSizeClass: SizeClass

    public init(
        id: String,
        size: CGSize,
        safeArea: Insets,
        scale: CGFloat,
        idiom: Idiom,
        horizontalSizeClass: SizeClass,
        verticalSizeClass: SizeClass = .regular
    ) {
        self.id = id
        self.size = size
        self.safeArea = safeArea
        self.scale = scale
        self.idiom = idiom
        self.horizontalSizeClass = horizontalSizeClass
        self.verticalSizeClass = verticalSizeClass
    }

    public static func == (a: Self, b: Self) -> Bool { a.id == b.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }

    /// iPhone 17 Pro, 402 x 874 pt @3x.
    public static let iPhone17Pro = SnapshotDevice(
        id: "iPhone17Pro", size: CGSize(width: 402, height: 874),
        safeArea: Insets(top: 62, bottom: 34), scale: 3, idiom: .phone, horizontalSizeClass: .compact
    )

    /// iPhone 17 Pro Max, 440 x 956 pt @3x.
    public static let iPhone17ProMax = SnapshotDevice(
        id: "iPhone17ProMax", size: CGSize(width: 440, height: 956),
        safeArea: Insets(top: 62, bottom: 34), scale: 3, idiom: .phone, horizontalSizeClass: .compact
    )

    /// The foldable unfolded (iPhone Duo inner screen, 669 x 951 pt @3x). At this width an app
    /// should switch to its two-pane layout, so the frame reports a regular horizontal size class.
    /// Safe area values are an estimate; replace them with values read from the simulator.
    public static let foldableUnfolded = SnapshotDevice(
        id: "FoldableUnfolded", size: CGSize(width: 669, height: 951),
        safeArea: Insets(top: 32, bottom: 20), scale: 3, idiom: .phone, horizontalSizeClass: .regular
    )

    /// The foldable folded (iPhone Duo cover screen, 466 x 678 pt @3x). Not in the default matrix.
    public static let foldableCover = SnapshotDevice(
        id: "FoldableCover", size: CGSize(width: 466, height: 678),
        safeArea: Insets(top: 32, bottom: 20), scale: 3, idiom: .phone, horizontalSizeClass: .compact
    )

    /// iPad Pro 11-inch (M4), 834 x 1210 pt @2x, portrait.
    public static let iPad = SnapshotDevice(
        id: "iPad11", size: CGSize(width: 834, height: 1210),
        safeArea: Insets(top: 24, bottom: 20), scale: 2, idiom: .pad, horizontalSizeClass: .regular
    )

    public static let standard: [SnapshotDevice] = [.iPhone17Pro, .iPhone17ProMax, .foldableUnfolded, .iPad]
}

/// A locale for the matrix. `pseudo` renders English strings through `PseudoLocalizer`.
public struct SnapshotLocale: Sendable, Hashable {
    /// Short form used in snapshot file names.
    public var id: String
    public var identifier: String
    /// The `.lproj` folder strings are read from.
    public var stringsLanguage: String
    public var pseudo: PseudoLocalizer?

    public init(id: String, identifier: String, stringsLanguage: String? = nil, pseudo: PseudoLocalizer? = nil) {
        self.id = id
        self.identifier = identifier
        self.stringsLanguage = stringsLanguage ?? Locale(identifier: identifier).language.languageCode?.identifier ?? identifier
        self.pseudo = pseudo
    }

    public static let en = SnapshotLocale(id: "en", identifier: "en_US")
    public static let fr = SnapshotLocale(id: "fr", identifier: "fr_FR")
    /// Accented, bracketed, about 40% longer. Uses the English strings as its source.
    /// `en-XA` is the conventional tag for an accented pseudo-locale.
    public static let pseudo = SnapshotLocale(id: "pseudo", identifier: "en_XA", stringsLanguage: "en", pseudo: .standard)

    public static let standard: [SnapshotLocale] = [.en, .fr, .pseudo]

    public var locale: Locale { Locale(identifier: identifier) }

    /// Applies the pseudo transform to a fixture string; other locales return it unchanged.
    /// Use it for text that comes from test fixtures rather than from a strings table.
    public func text(_ s: String) -> String { pseudo?.localize(s) ?? s }

    /// Looks `key` up in `bundle` for this locale's language (String Catalogs compile to
    /// `.lproj` tables, so this works with `.xcstrings` too), then applies the pseudo transform.
    /// Falls back to the development language, then to the key.
    public func string(_ key: String, table: String? = nil, bundle: Bundle = .main) -> String {
        let localized: String
        if let path = bundle.path(forResource: stringsLanguage, ofType: "lproj"), let lproj = Bundle(path: path) {
            localized = lproj.localizedString(forKey: key, value: nil, table: table)
        } else {
            localized = bundle.localizedString(forKey: key, value: nil, table: table)
        }
        return text(localized)
    }
}

/// One cell of the matrix.
public struct SnapshotVariant: Sendable, Hashable {
    public var device: SnapshotDevice
    public var appearance: SnapshotAppearance
    public var contentSize: SnapshotContentSize
    public var locale: SnapshotLocale

    public init(device: SnapshotDevice, appearance: SnapshotAppearance, contentSize: SnapshotContentSize, locale: SnapshotLocale) {
        self.device = device
        self.appearance = appearance
        self.contentSize = contentSize
        self.locale = locale
    }

    /// File-name friendly: `iPhone17Pro-dark-ax5-fr`.
    public var name: String { "\(device.id)-\(appearance.rawValue)-\(contentSize.shortName)-\(locale.id)" }
}

/// The axes of the matrix. The default is 4 devices x 2 appearances x 4 sizes x 3 locales = 96
/// images per view. Narrow it per call when a component does not need every axis.
public struct SnapshotMatrix: Sendable, Hashable {
    public var devices: [SnapshotDevice]
    public var appearances: [SnapshotAppearance]
    public var contentSizes: [SnapshotContentSize]
    public var locales: [SnapshotLocale]

    public init(
        devices: [SnapshotDevice] = SnapshotDevice.standard,
        appearances: [SnapshotAppearance] = SnapshotAppearance.allCases,
        contentSizes: [SnapshotContentSize] = SnapshotContentSize.allCases,
        locales: [SnapshotLocale] = SnapshotLocale.standard
    ) {
        self.devices = devices
        self.appearances = appearances
        self.contentSizes = contentSizes
        self.locales = locales
    }

    /// Every axis at its default.
    public static let standard = SnapshotMatrix()

    /// One device, both appearances, default and AX5, English and pseudo: a cheap PR smoke set.
    public static let smoke = SnapshotMatrix(
        devices: [.iPhone17Pro],
        contentSizes: [.large, .accessibility5],
        locales: [.en, .pseudo]
    )

    /// Cells in a stable order: device, then appearance, then size, then locale.
    public var variants: [SnapshotVariant] {
        var out: [SnapshotVariant] = []
        for d in devices {
            for a in appearances {
                for s in contentSizes {
                    for l in locales { out.append(SnapshotVariant(device: d, appearance: a, contentSize: s, locale: l)) }
                }
            }
        }
        return out
    }

    public var count: Int { devices.count * appearances.count * contentSizes.count * locales.count }

    public func with(devices: [SnapshotDevice]) -> Self { var m = self; m.devices = devices; return m }
    public func with(appearances: [SnapshotAppearance]) -> Self { var m = self; m.appearances = appearances; return m }
    public func with(contentSizes: [SnapshotContentSize]) -> Self { var m = self; m.contentSizes = contentSizes; return m }
    public func with(locales: [SnapshotLocale]) -> Self { var m = self; m.locales = locales; return m }
}

extension View {
    /// Applies a variant's environment: locale, layout direction, Dynamic Type and color scheme.
    /// Useful on its own for previews of a given cell.
    public func snapshotEnvironment(_ variant: SnapshotVariant) -> some View {
        self
            .environment(\.locale, variant.locale.locale)
            .environment(\.dynamicTypeSize, variant.contentSize.dynamicTypeSize)
            .environment(\.colorScheme, variant.appearance.colorScheme)
    }
}
