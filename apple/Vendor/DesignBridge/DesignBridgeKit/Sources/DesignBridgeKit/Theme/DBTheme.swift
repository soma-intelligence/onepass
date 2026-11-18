import SwiftUI

/// Spacing scale on the 4 pt grid (UX-SPACE-01).
public struct DBSpacing: Sendable, Hashable {
    public var xs: CGFloat
    public var s: CGFloat
    public var m: CGFloat
    public var l: CGFloat
    public var xl: CGFloat
    public var xxl: CGFloat

    public init(xs: CGFloat = 4, s: CGFloat = 8, m: CGFloat = 12, l: CGFloat = 16, xl: CGFloat = 24, xxl: CGFloat = 32) {
        self.xs = xs
        self.s = s
        self.m = m
        self.l = l
        self.xl = xl
        self.xxl = xxl
    }
}

/// The look every primitive reads. Apps fill it from their generated tokens
/// (`dbridge gen`), so DesignBridgeKit itself carries no branding.
///
/// Every requirement has a default in the protocol extension, so a conforming
/// type only overrides what its tokens define.
public protocol DBTheme: Sendable {
    /// Tint for the one primary action and for toast actions (UX-GLASS-04).
    var accent: Color { get }
    var success: Color { get }
    var warning: Color { get }
    var error: Color { get }
    var info: Color { get }
    var textPrimary: Color { get }
    var textSecondary: Color { get }
    /// Background of the scrolling sheet in `DBScrollHero`.
    var sheetBackground: Color { get }
    /// Fill of skeleton placeholders.
    var skeleton: Color { get }
    /// Top corner radius of the `DBScrollHero` sheet.
    var sheetCornerRadius: CGFloat { get }
    var spacing: DBSpacing { get }
    /// Text style of toast messages. Use a Dynamic Type style (UX-DT-01).
    var toastFont: Font { get }
}

public extension DBTheme {
    var accent: Color { .accentColor }
    var success: Color { .green }
    var warning: Color { .orange }
    var error: Color { .red }
    var info: Color { .blue }
    var textPrimary: Color { .primary }
    var textSecondary: Color { .secondary }
    var sheetBackground: Color { DBPlatformColor.background }
    var skeleton: Color { Color.gray.opacity(0.22) }
    var sheetCornerRadius: CGFloat { 28 }
    var spacing: DBSpacing { DBSpacing() }
    var toastFont: Font { .subheadline.weight(.semibold) }
}

/// A theme made of stored values, convenient for generated tokens:
///
/// ```swift
/// let theme = DBStandardTheme(accent: Tokens.Color.accent, sheetCornerRadius: Tokens.Radius.sheet)
/// RootView().dbTheme(theme)
/// ```
public struct DBStandardTheme: DBTheme {
    public var accent: Color
    public var success: Color
    public var warning: Color
    public var error: Color
    public var info: Color
    public var textPrimary: Color
    public var textSecondary: Color
    public var sheetBackground: Color
    public var skeleton: Color
    public var sheetCornerRadius: CGFloat
    public var spacing: DBSpacing
    public var toastFont: Font

    public init(
        accent: Color = .accentColor,
        success: Color = .green,
        warning: Color = .orange,
        error: Color = .red,
        info: Color = .blue,
        textPrimary: Color = .primary,
        textSecondary: Color = .secondary,
        sheetBackground: Color = DBPlatformColor.background,
        skeleton: Color = Color.gray.opacity(0.22),
        sheetCornerRadius: CGFloat = 28,
        spacing: DBSpacing = DBSpacing(),
        toastFont: Font = .subheadline.weight(.semibold)
    ) {
        self.accent = accent
        self.success = success
        self.warning = warning
        self.error = error
        self.info = info
        self.textPrimary = textPrimary
        self.textSecondary = textSecondary
        self.sheetBackground = sheetBackground
        self.skeleton = skeleton
        self.sheetCornerRadius = sheetCornerRadius
        self.spacing = spacing
        self.toastFont = toastFont
    }
}

/// System colours that differ by platform.
public enum DBPlatformColor {
    public static var background: Color {
        #if os(watchOS)
        Color.black
        #elseif canImport(UIKit)
        Color(uiColor: .systemBackground)
        #elseif canImport(AppKit)
        Color(nsColor: .windowBackgroundColor)
        #else
        Color.white
        #endif
    }
}

extension EnvironmentValues {
    /// The active DesignBridgeKit theme. Defaults to `DBStandardTheme()`.
    @Entry public var dbTheme: any DBTheme = DBStandardTheme()
}

public extension View {
    /// Injects the theme every DesignBridgeKit primitive below reads.
    func dbTheme(_ theme: some DBTheme) -> some View {
        environment(\.dbTheme, theme)
    }
}
