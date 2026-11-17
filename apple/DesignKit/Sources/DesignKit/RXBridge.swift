import DesignBridgeKit
import SwiftUI

// The RX look on the DesignBridge primitives: one theme filled from the generated Penpot tokens,
// one root modifier (toast host, theme, UI test launch overrides) and the RX names of the shared
// behaviours (press, rolling numbers, states), so every RX screen behaves like every other
// DesignBridge app.

extension Theme.RX {
    /// The DesignBridgeKit theme of the RX look, from the Penpot tokens only.
    public static var bridgeTheme: DBStandardTheme {
        DBStandardTheme(
            accent: Palette.accent.color,
            success: Palette.positive.color,
            warning: Palette.warning.color,
            error: Palette.negative.color,
            info: Palette.accentText.color,
            textPrimary: Palette.textPrimary.color,
            textSecondary: Palette.textSecondary.color,
            sheetBackground: Palette.pageBackground.color,
            skeleton: Palette.field.color,
            sheetCornerRadius: Radius.pageSheet,
            spacing: margins,
            toastFont: toastFont)
    }

    /// The one margin set of every RX screen: the Penpot spacing tokens.
    public static let margins = DBSpacing(xs: Space.xs, s: Space.s, m: Space.m, l: Space.l, xl: Space.xl, xxl: Space.xxl)

    /// Callout medium, scaled with Dynamic Type from its text style.
    static var toastFont: Font {
        let spec = Typography.calloutMedium.spec
        if Inter.isAvailable {
            return .custom(Inter.family, size: spec.size, relativeTo: Typography.calloutMedium.textStyle)
                .weight(Typography.calloutMedium.weight)
        }
        return .callout.weight(Typography.calloutMedium.weight)
    }
}

extension View {
    /// Once at the root of a window: the DesignBridge toast host and theme of the RX look, plus
    /// the launch overrides of the UI tests (`-DBColorScheme`, `-DBDynamicTypeSize`,
    /// `-DBReduceMotion`, Debug only).
    public func rxBridgeRoot() -> some View {
        dbToastHost()
            .dbTheme(Theme.RX.bridgeTheme)
            .dbLaunchOverrides()
    }

    /// The RX press: DesignBridge's 0.97 scale on the snappy spring (dims under Reduce Motion).
    public func rxPress() -> some View {
        buttonStyle(.dbPress)
    }
}

/// A number of the RX look: rolling digits (`DBNumber`) in an RX typography.
public struct RXNumber: View {
    let value: Double
    let format: DBNumberFormat
    let typography: Theme.RX.Typography

    public init(_ value: Int, typography: Theme.RX.Typography) {
        self.value = Double(value)
        self.format = .integer
        self.typography = typography
    }

    public init(_ value: Double, format: DBNumberFormat, typography: Theme.RX.Typography) {
        self.value = value
        self.format = format
        self.typography = typography
    }

    public var body: some View {
        DBNumber(value, format: format)
            .rxFont(typography)
    }
}
