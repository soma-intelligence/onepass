import CoreText
import SwiftUI
#if os(iOS) || os(visionOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

/// The RX look (Revolut-style structure on the Kelid identity): grouped cards on a grey or black
/// page, photo heroes under a rounded page sheet, round glass buttons, white glyphs on coloured
/// discs, a floating pill tab bar. The colours, spacing, radii and typographies come from the
/// Penpot file through `RXTokens+Generated.swift` (`dbridge export` then `dbridge gen`, see
/// Soma_Tools/design-bridge), so a screen never picks its own number or colour. Values that Penpot
/// does not hold yet (metrics, disc hues, the gutter, two radii) stay here, marked as code-owned.
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

            /// A generated Penpot colour token.
            init(_ token: RXPenpot.ColorToken) {
                func tone(_ c: RXPenpot.RGBA) -> Tone { Tone(red: c.red, green: c.green, blue: c.blue, alpha: c.alpha) }
                self.init(light: tone(token.light), dark: tone(token.dark))
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
            public static let pageBackground = Token(RXPenpot.Colors.bgPage)
            public static let cardBackground = Token(RXPenpot.Colors.bgCard)
            public static let raisedBackground = Token(RXPenpot.Colors.bgRaised)
            public static let glass = Token(RXPenpot.Colors.bgGlass)
            public static let field = Token(RXPenpot.Colors.bgField)
            public static let textPrimary = Token(RXPenpot.Colors.textPrimary)
            public static let textSecondary = Token(RXPenpot.Colors.textSecondary)
            public static let textTertiary = Token(RXPenpot.Colors.textTertiary)
            public static let separator = Token(RXPenpot.Colors.separator)
            public static let accent = Token(RXPenpot.Colors.accentBase)
            public static let accentText = Token(RXPenpot.Colors.accentText)
            public static let accentSoft = Token(RXPenpot.Colors.accentSoft)
            public static let onAccent = Token(RXPenpot.Colors.onAccent)
            public static let positive = Token(RXPenpot.Colors.positive)
            public static let negative = Token(RXPenpot.Colors.negative)
            public static let warning = Token(RXPenpot.Colors.warning)
            public static let tabBar = Token(RXPenpot.Colors.tabBar)
            public static let tabActive = Token(RXPenpot.Colors.tabActive)

            /// Every token with its Penpot name, for the parity test against the generated manifest.
            public static let all: [(name: String, token: Token)] = [
                ("bg.page", pageBackground), ("bg.card", cardBackground), ("bg.raised", raisedBackground),
                ("bg.glass", glass), ("bg.field", field), ("text.primary", textPrimary),
                ("text.secondary", textSecondary), ("text.tertiary", textTertiary), ("separator", separator),
                ("accent.base", accent), ("accent.text", accentText), ("accent.soft", accentSoft),
                ("on.accent", onAccent), ("positive", positive), ("negative", negative), ("warning", warning),
                ("tab.bar", tabBar), ("tab.active", tabActive),
            ]
        }

        /// The disc hues behind white glyphs (same in light and dark). Code-owned: not in Penpot yet.
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
            public static let xs = RXPenpot.Spacing.spaceXs
            public static let s = RXPenpot.Spacing.spaceSm
            public static let m = RXPenpot.Spacing.spaceMd
            public static let l = RXPenpot.Spacing.spaceLg
            public static let xl = RXPenpot.Spacing.spaceXl
            public static let xxl = RXPenpot.Spacing.space2xl
            /// Half of space.xs, between a title and its subtitle only. Code-owned: the Penpot rows
            /// use a 2 pt gap that has no token yet.
            public static let xxs = RXPenpot.Spacing.spaceXs / 2
            /// Side margin of a screen and gap between the cards of a page (space.lg).
            public static let gutter = RXPenpot.Spacing.spaceLg
        }

        /// The radius tokens (radius.chip to radius.pill).
        public enum Radius {
            public static let chip = RXPenpot.Radius.radiusChip
            public static let tile = RXPenpot.Radius.radiusTile
            public static let card = RXPenpot.Radius.radiusCard
            public static let sheet = RXPenpot.Radius.radiusSheet
            /// A capsule (radius.pill).
            public static let pill = RXPenpot.Radius.radiusPill
            /// The page sheet that starts under a photo hero. Code-owned: not in Penpot yet.
            public static let pageSheet: CGFloat = 28
            /// A perk tile (Get more from Plus): the card radius, as shipped. Code-owned: not in
            /// Penpot yet.
            public static let perk: CGFloat = RXPenpot.Radius.radiusCard
            /// A row of the Mac sidebar and its search field. Code-owned: not in Penpot yet.
            public static let macRow: CGFloat = 10
        }

        /// Measured sizes of the building blocks. Code-owned: not in Penpot yet.
        public enum Metrics {
            /// A round glass button.
            public static let glassButton: CGFloat = 44
            /// The smallest hit area of a control (Apple HIG, UX-A11Y hit area).
            public static let minTapTarget: CGFloat = 44
            /// The disc of a quick action.
            public static let actionDisc: CGFloat = 48
            /// The width of a quick action column (disc and label).
            public static let actionWidth: CGFloat = 92
            /// The lead (site tile, coloured disc) of an item row: 44, larger logos (device
            /// feedback 2026-11-16).
            public static let itemLead: CGFloat = 44
            /// The glyph of a menu row.
            public static let menuGlyph: CGFloat = 24
            /// Row pitches: an item row (two lines) and a menu row (one line).
            public static let itemPitch: CGFloat = 64
            public static let menuPitch: CGFloat = 56
            /// The plan card and a perk tile: their smallest height (they grow with the text).
            public static let planCardHeight: CGFloat = 156
            public static let perkTileHeight: CGFloat = 220
            /// The inner padding of the plan card and the width of its art.
            public static let planCardPadding: CGFloat = 20
            public static let planCardArtWidth: CGFloat = 210
            /// The small disc of a perk tile.
            public static let perkGlyph: CGFloat = 32
            /// A perk tile in the paging carousel: wide enough for its title, narrow enough for
            /// the next tile to peek on an iPhone. It grows with the text size up to the maximum.
            public static let perkCarouselTileWidth: CGFloat = 240
            public static let perkCarouselTileMaxWidth: CGFloat = 320
            /// The disc of a stat tile (Watchtower).
            public static let statDisc: CGFloat = 36
            /// The smallest height of a count badge in a menu row.
            public static let badgeHeight: CGFloat = 22
            /// Account pictures: Réglages hero and QR page, Mac Settings banner, Mac sidebar.
            public static let avatarLarge: CGFloat = 72
            public static let avatarMedium: CGFloat = 52
            public static let avatarSmall: CGFloat = 32
            /// The largest side of the profile QR code.
            public static let profileQR: CGFloat = 240
            /// Mac sidebar: a row, the account row, a row glyph frame, the add button, a tag dot.
            public static let macRowHeight: CGFloat = 34
            public static let macAccountRowHeight: CGFloat = 60
            public static let macRowGlyph: CGFloat = 20
            public static let macAddButton: CGFloat = 22
            public static let macTagDot: CGFloat = 10
            /// The floating tab bar and its search button.
            public static let tabBarHeight: CGFloat = 64
            /// Height of the photo hero above the page sheet (Home and Settings).
            public static let heroHeight: CGFloat = 470

            /// The glyph inside a disc of diameter `d`: half of it, rounded.
            public static func discGlyph(diameter d: CGFloat) -> CGFloat {
                (d * 0.5).rounded()
            }
            /// The verification code: digits (D-CODE-SIZE, app-owned) and the timer ring around
            /// the seconds left.
            public static var codeDigits: CGFloat { Typography.monoCode.spec.size }
            public static let codeRing: CGFloat = 36
            /// The ring's stroke, and the heavier stroke of the last seconds (not colour alone).
            public static let codeRingStroke: CGFloat = 3
            public static let codeRingUrgentStroke: CGFloat = 5
            /// A favourite tile of the carousel: its logo and its width (the next one peeks).
            public static let favoriteLogo: CGFloat = 60
            public static let favoriteWidth: CGFloat = 84
            /// The lead logo of an item row: the item lead (larger logos, device feedback 2026-11-16).
            public static let itemLogo: CGFloat = itemLead
        }

        /// SF Symbols drawn inside fixed geometry (a disc, a chevron, a ring): their size follows
        /// the shape, not Dynamic Type, so it lives here with the other measured sizes.
        public enum Glyph {
            public static let chevron: CGFloat = 14
            public static let menu: CGFloat = 20
            public static let action: CGFloat = 20
            /// Mac sidebar: the brand mark, a row glyph, small controls (add, chevrons), a vault initial.
            public static let macBrand: CGFloat = 16
            public static let macRow: CGFloat = 14
            public static let macSmall: CGFloat = 11
            public static let macInitial: CGFloat = 9

            /// The SF Symbol font at a fixed size, for glyphs inside fixed shapes only.
            public static func font(_ size: CGFloat, weight: Font.Weight = .semibold) -> Font {
                .system(size: size, weight: weight)
            }

            /// The digits of the verification code: the Mono code typography (Inter, tabular
            /// digits) at `size`, the scaled `Metrics.codeDigits`.
            public static func codeFont(size: CGFloat) -> Font {
                Typography.monoCode.font(size: size)
            }
        }

        /// Colours that are not Penpot tokens yet (the alert washes of Watchtower). Code-owned until
        /// the Penpot agent adds them; dbridge drift lists them. Both stops of each wash keep 4.5:1
        /// under white Footnote text (alert 4.7 and 6.3, positive 4.7 and 6.3).
        public enum Wash {
            public static let alertTones = [Tone(css: "#D33B39")!, Tone(css: "#B42A2D")!]
            public static let positiveTones = [Tone(css: "#1D8450")!, Tone(css: "#0F6E41")!]
            public static let alert: [Color] = alertTones.map(\.color)
            public static let positive: [Color] = positiveTones.map(\.color)
            /// The initials disc of an account without a photo.
            public static let avatar: [Color] = [Tone(css: "#8B89F0")!.color, Tone(css: "#4B48C9")!.color]
            /// Under a perk tile's art while it loads.
            public static let artPlaceholder = Tone(css: "#1C1C1C")!.color
        }

        /// The veils over photos and the white text on them. `flat` is Reduce Transparency or
        /// Increase Contrast (`Theme.Wash.isFlat`): a stronger veil and secondary text at full
        /// opacity. Code-owned.
        public enum Veil {
            /// The dark scrim of a hero photo: top, middle, bottom.
            public static func hero(flat: Bool) -> [Double] { flat ? [0.55, 0.5, 0.75] : [0.25, 0.05, 0.55] }
            /// The white veil of a light hero photo: top, middle, bottom.
            public static func lightHero(flat: Bool) -> [Double] { flat ? [0.6, 0.55, 0.75] : [0.15, 0.1, 0.35] }
            /// The dark gradient over a perk tile's art: at its middle and at its bottom.
            public static func perk(flat: Bool) -> (middle: Double, bottom: Double) { flat ? (0.45, 0.8) : (0, 0.62) }
            /// The even scrim of the Mac Settings banner.
            public static func banner(flat: Bool) -> Double { flat ? 0.5 : 0.2 }
            /// Secondary white text on a photo or a glass panel.
            public static func secondaryText(flat: Bool) -> Double { flat ? 1 : 0.72 }
        }

        /// The one shadow of raised RX controls (a quick action disc on a plain page).
        public enum Shadow {
            public static let raisedOpacity: Double = 0.06
            public static let raisedRadius: CGFloat = 5
            public static let raisedY: CGFloat = 2
        }

        // MARK: Typography

        /// The Penpot typographies (OnePass/Display to OnePass/Mono code), drawn in the system face.
        public enum Typography: String, CaseIterable, Sendable {
            case display, displaySmall, largeTitle, title, headline, body, bodyMedium, callout, calloutMedium, footnote,
                footnoteBold, caption, monoCode

            /// The generated Penpot typography.
            var token: RXPenpot.TypeToken {
                switch self {
                case .display: RXPenpot.Typography.display
                case .displaySmall: RXPenpot.Typography.displaySmall
                case .largeTitle: RXPenpot.Typography.largeTitle
                case .title: RXPenpot.Typography.title
                case .headline: RXPenpot.Typography.headline
                case .body: RXPenpot.Typography.body
                case .bodyMedium: RXPenpot.Typography.bodyMedium
                case .callout: RXPenpot.Typography.callout
                case .calloutMedium: RXPenpot.Typography.calloutMedium
                case .footnote: RXPenpot.Typography.footnote
                case .footnoteBold: RXPenpot.Typography.footnoteBold
                case .caption: RXPenpot.Typography.caption
                case .monoCode: RXPenpot.Typography.monoCode
                }
            }

            /// Size, weight (100 to 900), letter spacing and line height (a multiple of the size),
            /// exactly as the Penpot typography writes them.
            public var spec: (size: CGFloat, weight: Int, tracking: CGFloat, lineHeight: CGFloat) {
                let t = token
                return (t.size, t.weight, t.tracking, t.lineHeight)
            }

            /// The system text style it scales with under Dynamic Type (from designbridge.json).
            public var textStyle: Font.TextStyle {
                token.textStyle
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

            /// The font at `size` (the scaled size of the typography, so Dynamic Type is already in
            /// it): Inter as in the Penpot file, with tabular digits for the code. The system face
            /// stands in if Inter could not be registered.
            public func font(size: CGFloat) -> Font {
                let font: Font = Theme.RX.Inter.isAvailable
                    ? .custom(Theme.RX.Inter.family, fixedSize: size).weight(weight)
                    : .system(size: size, weight: weight)
                return self == .monoCode ? font.monospacedDigit() : font
            }
        }

        /// Inter 4 (variable, opsz and wght axes, Latin subset), bundled with its SIL Open Font
        /// Licence (Resources/Fonts/Inter-OFL.txt). Registered for this process on first use.
        public enum Inter {
            public static let family = "Inter"

            /// The SIL Open Font Licence text shipped with the font.
            public static var licenceURL: URL? {
                Bundle.module.url(forResource: "Inter-OFL", withExtension: "txt")
            }

            /// True once the bundled font is registered (or was already).
            public static let isAvailable: Bool = {
                guard let url = Bundle.module.url(forResource: "InterVariable", withExtension: "ttf") else { return false }
                var error: Unmanaged<CFError>?
                if CTFontManagerRegisterFontsForURL(url as CFURL, .process, &error) { return true }
                // Already registered (a second bundle or a previous call) still counts.
                let code = error.map { CFErrorGetCode($0.takeRetainedValue()) }
                return code == CTFontManagerError.alreadyRegistered.rawValue
            }()
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
