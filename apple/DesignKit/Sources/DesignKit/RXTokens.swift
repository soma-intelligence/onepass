import SwiftUI
#if os(iOS) || os(visionOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

/// The RX look (Revolut-style structure on the OnePass identity): grouped cards on a grey or black
/// page, photo heroes under a rounded page sheet, round glass buttons, white glyphs on coloured
/// discs, a floating pill tab bar. Every value here mirrors a token of the Penpot file
/// (penpot-lab/screens/rx-tokens.js), so a screen never picks its own number or colour.
///
/// The look ships behind `RXDesign` (off by default); the screens keep their current style while
/// it is off.
extension Theme {
    public enum RX {
        // MARK: Colour

        /// One colour as red, green, blue and alpha in 0...1.
        public struct Tone: Equatable, Sendable {
            public let red: Double
            public let green: Double
            public let blue: Double
            public let alpha: Double

            public init(red: Double, green: Double, blue: Double, alpha: Double = 1) {
                self.red = red
                self.green = green
                self.blue = blue
                self.alpha = alpha
            }

            /// `#RRGGBB` or `rgba(r,g,b,a)` as the Penpot tokens write them. Nil for anything else.
            public init?(css: String) {
                let s = css.trimmingCharacters(in: .whitespaces).lowercased()
                if s.hasPrefix("#") {
                    let hex = s.dropFirst()
                    guard hex.count == 6, let v = UInt32(hex, radix: 16) else { return nil }
                    self.init(
                        red: Double((v >> 16) & 0xFF) / 255, green: Double((v >> 8) & 0xFF) / 255,
                        blue: Double(v & 0xFF) / 255)
                    return
                }
                guard s.hasPrefix("rgba("), s.hasSuffix(")") else { return nil }
                let parts = s.dropFirst(5).dropLast().split(separator: ",").map {
                    Double($0.trimmingCharacters(in: .whitespaces))
                }
                guard parts.count == 4, let r = parts[0], let g = parts[1], let b = parts[2], let a = parts[3],
                    (0...255).contains(r), (0...255).contains(g), (0...255).contains(b), (0...1).contains(a)
                else { return nil }
                self.init(red: r / 255, green: g / 255, blue: b / 255, alpha: a)
            }

            public var color: Color {
                Color(.sRGB, red: red, green: green, blue: blue, opacity: alpha)
            }
        }

        /// A colour token: its light and dark values. `color` follows the appearance of the view it
        /// is drawn in.
        public struct Token: Equatable, Sendable {
            public let light: Tone
            public let dark: Tone

            public init(light: Tone, dark: Tone) {
                self.light = light
                self.dark = dark
            }

            /// Both values in the Penpot notation. A typo in this file is a programmer error.
            init(_ light: String, _ dark: String) {
                guard let l = Tone(css: light), let d = Tone(css: dark) else {
                    preconditionFailure("RX token: unreadable value \(light) / \(dark)")
                }
                self.init(light: l, dark: d)
            }

            /// The value for `scheme`.
            public func tone(for scheme: ColorScheme) -> Tone {
                scheme == .dark ? dark : light
            }

            /// The colour, resolved against the trait (iPhone, iPad, Vision) or the appearance (Mac)
            /// at draw time. The watch is always dark.
            public var color: Color {
                #if os(iOS) || os(visionOS)
                let light = self.light, dark = self.dark
                return Color(uiColor: UIColor { traits in
                    let t = traits.userInterfaceStyle == .dark ? dark : light
                    return UIColor(red: t.red, green: t.green, blue: t.blue, alpha: t.alpha)
                })
                #elseif os(macOS)
                let light = self.light, dark = self.dark
                return Color(nsColor: NSColor(name: nil) { appearance in
                    let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                    let t = isDark ? dark : light
                    return NSColor(srgbRed: t.red, green: t.green, blue: t.blue, alpha: t.alpha)
                })
                #else
                return dark.color
                #endif
            }
        }

        /// The colour tokens of the Penpot sets OnePass/Light and OnePass/Dark.
        public enum Palette {
            public static let pageBackground = Token("#F2F2F7", "#000000")
            public static let cardBackground = Token("#FFFFFF", "#161618")
            public static let raisedBackground = Token("#FFFFFF", "#2C2C2E")
            public static let glass = Token("rgba(255,255,255,0.72)", "rgba(118,118,128,0.24)")
            public static let field = Token("#E9E9EE", "#1F1F22")
            public static let textPrimary = Token("#0B0B0F", "#FFFFFF")
            public static let textSecondary = Token("#6B6B73", "#A1A1A6")
            public static let textTertiary = Token("#A0A0A8", "#6E6E73")
            public static let separator = Token("#E3E3E8", "#2A2A2E")
            public static let accent = Token("#5856D6", "#5856D6")
            public static let accentText = Token("#5856D6", "#A3A2E8")
            public static let accentSoft = Token("rgba(88,86,214,0.12)", "rgba(163,162,232,0.18)")
            public static let onAccent = Token("#FFFFFF", "#FFFFFF")
            public static let positive = Token("#11A866", "#3FD68F")
            public static let negative = Token("#E5484D", "#FF5B61")
            public static let warning = Token("#E39A00", "#FFB020")
            public static let tabBar = Token("rgba(255,255,255,0.86)", "rgba(44,44,46,0.82)")
            public static let tabActive = Token("rgba(11,11,15,0.08)", "rgba(255,255,255,0.14)")

            /// Every token with its Penpot name, for the tests and a future token export.
            public static let all: [(name: String, token: Token)] = [
                ("bg.page", pageBackground), ("bg.card", cardBackground), ("bg.raised", raisedBackground),
                ("bg.glass", glass), ("bg.field", field), ("text.primary", textPrimary),
                ("text.secondary", textSecondary), ("text.tertiary", textTertiary), ("separator", separator),
                ("accent.base", accent), ("accent.text", accentText), ("accent.soft", accentSoft),
                ("on.accent", onAccent), ("positive", positive), ("negative", negative), ("warning", warning),
                ("tab.bar", tabBar), ("tab.active", tabActive),
            ]
        }

        /// The disc hues behind white glyphs (same in light and dark).
        public enum Hue {
            public static let red = Tone(css: "#FF5B61")!.color
            public static let orange = Tone(css: "#FF7A45")!.color
            public static let violet = Tone(css: "#A35BF0")!.color
            public static let blue = Tone(css: "#4A9BFF")!.color
            public static let teal = Tone(css: "#14B8A6")!.color
            public static let green = Tone(css: "#22C55E")!.color
            public static let indigo = Tone(css: "#5856D6")!.color
            public static let pink = Tone(css: "#EC4899")!.color
            public static let slate = Tone(css: "#64748B")!.color
        }

        // MARK: Spacing and radius

        /// The spacing tokens (space.xs to space.2xl).
        public enum Space {
            public static let xs: CGFloat = 4
            public static let s: CGFloat = 8
            public static let m: CGFloat = 12
            public static let l: CGFloat = 16
            public static let xl: CGFloat = 24
            public static let xxl: CGFloat = 32
            /// Side margin of a screen and gap between the cards of a page.
            public static let gutter: CGFloat = 16
        }

        /// The radius tokens (radius.chip to radius.pill).
        public enum Radius {
            public static let chip: CGFloat = 12
            public static let tile: CGFloat = 16
            public static let card: CGFloat = 24
            public static let sheet: CGFloat = 36
            /// The page sheet that starts under a photo hero.
            public static let pageSheet: CGFloat = 28
            /// A perk tile (Get more from Plus).
            public static let perk: CGFloat = 20
        }

        /// Measured sizes of the building blocks.
        public enum Metrics {
            /// A round glass button.
            public static let glassButton: CGFloat = 44
            /// The disc of a quick action.
            public static let actionDisc: CGFloat = 48
            /// The width of a quick action column (disc and label).
            public static let actionWidth: CGFloat = 92
            /// The lead (site tile, coloured disc) of an item row.
            public static let itemLead: CGFloat = 40
            /// The glyph of a menu row.
            public static let menuGlyph: CGFloat = 24
            /// Row pitches: an item row (two lines) and a menu row (one line).
            public static let itemPitch: CGFloat = 64
            public static let menuPitch: CGFloat = 56
            /// The plan card and a perk tile.
            public static let planCardHeight: CGFloat = 132
            public static let perkTileHeight: CGFloat = 220
            /// The floating tab bar and its search button.
            public static let tabBarHeight: CGFloat = 64
            /// Height of the photo hero above the page sheet (Home and Settings).
            public static let heroHeight: CGFloat = 470

            /// The glyph inside a disc of diameter `d`: half of it, rounded.
            public static func discGlyph(diameter d: CGFloat) -> CGFloat {
                (d * 0.5).rounded()
            }
        }

        // MARK: Typography

        /// The Penpot typographies (OnePass/Display to OnePass/Mono code), drawn in the system face.
        public enum Typography: String, CaseIterable, Sendable {
            case display, largeTitle, title, headline, body, bodyMedium, callout, calloutMedium, footnote,
                footnoteBold, caption, monoCode

            /// Size, weight (100 to 900), letter spacing and line height (a multiple of the size),
            /// exactly as rx-tokens.js writes them.
            public var spec: (size: CGFloat, weight: Int, tracking: CGFloat, lineHeight: CGFloat) {
                switch self {
                case .display: (56, 700, -2, 1.0)
                case .largeTitle: (34, 700, -0.8, 1.1)
                case .title: (22, 600, -0.3, 1.2)
                case .headline: (17, 600, -0.2, 1.25)
                case .body: (17, 400, -0.2, 1.3)
                case .bodyMedium: (17, 500, -0.2, 1.3)
                case .callout: (15, 400, -0.1, 1.3)
                case .calloutMedium: (15, 500, -0.1, 1.3)
                case .footnote: (13, 400, 0, 1.3)
                case .footnoteBold: (13, 600, 0, 1.3)
                case .caption: (11, 600, 0.1, 1.2)
                case .monoCode: (28, 500, 1, 1.1)
                }
            }

            /// The system text style it scales with under Dynamic Type.
            public var textStyle: Font.TextStyle {
                switch self {
                case .display, .largeTitle: .largeTitle
                case .title: .title2
                case .headline: .headline
                case .body, .bodyMedium: .body
                case .callout, .calloutMedium: .callout
                case .footnote, .footnoteBold: .footnote
                case .caption: .caption2
                case .monoCode: .title
                }
            }

            public var weight: Font.Weight {
                Self.fontWeight(spec.weight)
            }

            /// The SwiftUI weight of a CSS weight (nearest step).
            public static func fontWeight(_ css: Int) -> Font.Weight {
                switch css {
                case ..<150: .ultraLight
                case ..<250: .thin
                case ..<350: .light
                case ..<450: .regular
                case ..<550: .medium
                case ..<650: .semibold
                case ..<750: .bold
                case ..<850: .heavy
                default: .black
                }
            }

            /// The space SwiftUI adds between lines for the Penpot line height at `size`.
            public static func lineSpacing(size: CGFloat, lineHeight: CGFloat) -> CGFloat {
                max(size * (lineHeight - 1.2), 0)
            }

            /// The font at `size` (the scaled size of the typography).
            public func font(size: CGFloat) -> Font {
                .system(size: size, weight: weight, design: self == .monoCode ? .monospaced : .default)
            }
        }
    }
}

/// Applies a Penpot typography: the size scales with Dynamic Type from its text style, with the
/// letter spacing and line height of the token.
private struct RXTextStyle: ViewModifier {
    let typography: Theme.RX.Typography
    @ScaledMetric private var size: CGFloat

    init(_ typography: Theme.RX.Typography) {
        self.typography = typography
        _size = ScaledMetric(wrappedValue: typography.spec.size, relativeTo: typography.textStyle)
    }

    func body(content: Content) -> some View {
        let spec = typography.spec
        content
            .font(typography.font(size: size))
            .tracking(spec.tracking * size / spec.size)
            .lineSpacing(Theme.RX.Typography.lineSpacing(size: size, lineHeight: spec.lineHeight))
    }
}

extension View {
    /// Text in one of the RX typographies.
    public func rxFont(_ typography: Theme.RX.Typography) -> some View {
        modifier(RXTextStyle(typography))
    }
}

/// The switch of the RX look: a per-device preference, off by default. Debug builds also take the
/// launch argument `-OnePassRX YES` (screenshots, demo data), which sets the default only: a stored
/// choice still wins.
public enum RXDesign {
    /// The defaults key of the choice.
    public static let storageKey = "onepass.design.rx"
    /// The launch argument of Debug builds.
    public static let launchArgument = "OnePassRX"

    /// Whether the look is on: the stored choice, else the launch argument, else off.
    public static func isOn(stored: Bool?, launchArgument: Bool?) -> Bool {
        stored ?? launchArgument ?? false
    }

    /// The default value of the stored choice for this launch.
    public static var launchDefault: Bool {
        #if DEBUG
        // A launch argument arrives as the string "YES" or "NO": `bool(forKey:)` reads both.
        let defaults = UserDefaults.standard
        return isOn(
            stored: nil,
            launchArgument: defaults.object(forKey: launchArgument) == nil ? nil : defaults.bool(forKey: launchArgument))
        #else
        return false
        #endif
    }
}
