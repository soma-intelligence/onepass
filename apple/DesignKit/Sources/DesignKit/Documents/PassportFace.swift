import SwiftUI

/// What a passport booklet shows: the user's own data, read from the chip or typed. Dates and the
/// sex letter come already formatted for display.
public struct PassportData {
    public var surname: String
    public var givenNames: String
    public var number: String
    public var nationality: String
    public var birthDate: String
    public var expiryDate: String
    public var sex: String
    /// The two TD3 lines, separated by a line break.
    public var mrz: String
    public var portrait: Image?
    public var status: ChipBadge.Status?
    public var readOn: Date?

    public init(
        surname: String = "", givenNames: String = "", number: String = "", nationality: String = "",
        birthDate: String = "", expiryDate: String = "", sex: String = "", mrz: String = "",
        portrait: Image? = nil, status: ChipBadge.Status? = nil, readOn: Date? = nil
    ) {
        self.surname = surname
        self.givenNames = givenNames
        self.number = number
        self.nationality = nationality
        self.birthDate = birthDate
        self.expiryDate = expiryDate
        self.sex = sex
        self.mrz = mrz
        self.portrait = portrait
        self.status = status
        self.readOn = readOn
    }
}

/// A passport as an evocative booklet (spec 2026-11-21 sections 4 and 7): a grained cover in the
/// family's tint with the document type and the country as text and the generic chip symbol, and
/// under it the data page (portrait, fields, MRZ) with the fixed notice "Copie numérique, non
/// officielle". Never a replica: no emblem, no seal, no guilloche, no hologram, no official font
/// or layout, and no share or export on the view.
///
/// Touching the cover opens it on its left edge (`rotation3DEffect`, soft spring of about 0.6 s);
/// a drag to the right closes it. Reduce Motion: a fade, no rotation, the reflection frozen.
/// `revealProgress` from 0 to 1 (animate it over `revealDuration`, linear) fades the portrait in,
/// then the rows one by one 40 ms apart, with a light tap at the end on iPhone. The number and the
/// MRZ stay masked while `secretsRevealed` is false. While the screen is captured (recording,
/// mirroring) the whole rendering is hidden, as revealed secrets are elsewhere in the app.
public struct PassportFace: View {
    @Environment(\.accessibilityReduceMotion) private var systemReduceMotion
    @Environment(\.documentReduceMotion) private var reduceMotionOverride
    #if os(iOS) || os(visionOS)
    @Environment(\.isSceneCaptured) private var captured
    #else
    private let captured = false
    #endif

    private let family: DocumentFamily
    private let data: PassportData
    @Binding private var isOpen: Bool
    private let revealProgress: Double
    private let secretsRevealed: Bool

    public init(
        family: DocumentFamily, data: PassportData, isOpen: Binding<Bool>, revealProgress: Double = 1,
        secretsRevealed: Bool
    ) {
        self.family = family
        self.data = data
        _isOpen = isOpen
        self.revealProgress = revealProgress
        self.secretsRevealed = secretsRevealed
    }

    /// TD3 booklet page, 125 x 88 mm.
    public static let aspectRatio: CGFloat = 125.0 / 88.0
    /// How long a full reveal takes: the portrait, then each row 40 ms after the previous one.
    public static var revealDuration: Double { DataPage.revealDuration }

    private var reduceMotion: Bool { reduceMotionOverride ?? systemReduceMotion }

    private var openAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.25) : .spring(duration: 0.6, bounce: 0.12)
    }

    private func setOpen(_ open: Bool) {
        guard open != isOpen else { return }
        withAnimation(openAnimation) { isOpen = open }
    }

    public var body: some View {
        GeometryReader { geo in
            let scale = geo.size.width / DataPage.designSize.width
            ZStack {
                if captured {
                    CapturedPlaceholder(family: family)
                } else {
                    DataPage(
                        family: family, data: data, revealProgress: revealProgress,
                        secretsRevealed: secretsRevealed
                    )
                    .frame(width: DataPage.designSize.width, height: DataPage.designSize.height)
                    .scaleEffect(scale, anchor: .topLeading)
                    .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
                    .documentSheen()
                    .clipShape(.rect(cornerRadius: 10 * scale, style: .continuous))
                    .opacity(isOpen ? 1 : 0)
                    .accessibilityHidden(!isOpen)
                    .gesture(
                        DragGesture(minimumDistance: 20)
                            .onEnded { value in
                                if value.translation.width > 60, abs(value.translation.height) < value.translation.width {
                                    setOpen(false)
                                }
                            },
                        including: isOpen ? .all : .subviews
                    )
                    .accessibilityAction(named: Text("passport.close", bundle: .module)) { setOpen(false) }

                    Cover(family: family)
                        .frame(width: DataPage.designSize.width, height: DataPage.designSize.height)
                        .scaleEffect(scale, anchor: .topLeading)
                        .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
                        .documentSheen()
                        .clipShape(.rect(cornerRadius: 10 * scale, style: .continuous))
                        .modifier(CoverHinge(angle: isOpen ? (reduceMotion ? 0 : -180) : 0, fade: reduceMotion && isOpen))
                        .allowsHitTesting(!isOpen)
                        .accessibilityHidden(isOpen)
                        .onTapGesture { setOpen(true) }
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel(coverLabel)
                        .accessibilityValue(coverValue)
                        .accessibilityHint(Text("passport.open", bundle: .module))
                        .accessibilityAddTraits(.isButton)
                        .accessibilityAction { setOpen(true) }
                        .accessibilityIdentifier("document.passport.cover")
                }
            }
        }
        .aspectRatio(Self.aspectRatio, contentMode: .fit)
        .shadow(color: .black.opacity(0.18), radius: 10, y: 6)
        .privacySensitive()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("document.passport")
    }

    private var coverLabel: Text { Text(family.documentTitle, bundle: .module) }

    /// The country printed on the cover, read after its title.
    private var coverValue: Text {
        family.countryTitle.map { Text($0, bundle: .module) } ?? Text(verbatim: "")
    }
}

// MARK: - Cover

/// The cover turns on its left edge. Past a quarter turn it shows its inner side and fades out, so
/// the open booklet stays inside its frame.
private struct CoverHinge: ViewModifier, Animatable {
    var angle: Double
    /// Reduce Motion: no turn, the cover fades away.
    var fade: Bool

    nonisolated var animatableData: Double {
        get { angle }
        set { angle = newValue }
    }

    func body(content: Content) -> some View {
        let past = abs(angle) > 90
        let opacity = fade ? 0 : (past ? max(0, (180 - abs(angle)) / 90) : 1)
        content
            .overlay {
                // The inner side of the cover: the plain tint, no titles.
                if past {
                    Rectangle().fill(.black.opacity(0.25)).accessibilityHidden(true)
                }
            }
            .rotation3DEffect(.degrees(angle), axis: (x: 0, y: 1, z: 0), anchor: .leading, perspective: 0.45)
            .opacity(opacity)
    }
}

private struct Cover: View {
    let family: DocumentFamily

    private var ink: Color { Theme.RX.Document.coverInk.color }

    var body: some View {
        ZStack {
            Rectangle().fill(family.coverTint)
            Grain().blendMode(.overlay).opacity(0.5)
            // The fold of the spine along the left edge.
            LinearGradient(colors: [.black.opacity(0.28), .clear], startPoint: .leading, endPoint: .init(x: 0.06, y: 0.5))
            VStack(spacing: 10) {
                if let country = family.countryTitle {
                    Text(country, bundle: .module)
                        .font(.system(size: 13, weight: .semibold))
                        .tracking(2.4)
                        .textCase(.uppercase)
                }
                Spacer(minLength: 0)
                Text(family.documentTitle, bundle: .module)
                    .font(.system(size: 26, weight: .semibold))
                    .tracking(5)
                    .textCase(.uppercase)
                Spacer(minLength: 0)
                ChipSymbol()
                    .stroke(ink, lineWidth: 1.6)
                    .frame(width: 34, height: 22)
            }
            .foregroundStyle(ink)
            .multilineTextAlignment(.center)
            .lineLimit(1)
            .minimumScaleFactor(0.6)
            .padding(.vertical, 30)
            .padding(.horizontal, 36)
        }
        .environment(\.dynamicTypeSize, .large)
    }
}

/// The generic electronic chip symbol (ICAO): a rectangle with a circle between two lines.
struct ChipSymbol: Shape {
    func path(in rect: CGRect) -> Path {
        var p = Path()
        p.addRoundedRect(in: rect, cornerSize: CGSize(width: 2, height: 2))
        let r = rect.height * 0.26
        let c = CGPoint(x: rect.midX, y: rect.midY)
        p.addEllipse(in: CGRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r))
        p.move(to: CGPoint(x: rect.minX, y: c.y - r))
        p.addLine(to: CGPoint(x: rect.maxX, y: c.y - r))
        p.move(to: CGPoint(x: rect.minX, y: c.y + r))
        p.addLine(to: CGPoint(x: rect.maxX, y: c.y + r))
        return p
    }
}

/// A fine leather grain: deterministic random specks, no pattern, no motif.
private struct Grain: View {
    var body: some View {
        Canvas(rendersAsynchronously: false) { context, size in
            var seed: UInt64 = 0x9E37_79B9_7F4A_7C15
            func next() -> Double {
                seed = seed &* 6364136223846793005 &+ 1442695040888963407
                return Double(seed >> 11) / Double(1 << 53)
            }
            let count = Int(size.width * size.height / 22)
            for _ in 0..<count {
                let x = next() * size.width, y = next() * size.height
                let light = next() > 0.5
                let rect = CGRect(x: x, y: y, width: 1.1, height: 1.1)
                context.fill(Path(ellipseIn: rect), with: .color(light ? .white.opacity(0.35) : .black.opacity(0.45)))
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// Drawn instead of the booklet while the screen is captured: the cover tint alone.
private struct CapturedPlaceholder: View {
    let family: DocumentFamily

    var body: some View {
        RoundedRectangle(cornerRadius: 10, style: .continuous)
            .fill(family.coverTint)
            .overlay {
                Image(systemName: "eye.slash")
                    .font(.title2)
                    .foregroundStyle(Theme.RX.Document.coverInk.color)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("passport.captured", bundle: .module))
    }
}

// MARK: - Data page

/// One line of the data page: a label and what is shown for it. A masked value shows bullets and
/// reads "masqué" to VoiceOver; the value itself is nowhere in the view.
struct PassportRow: Equatable {
    enum Kind: Equatable { case surname, givenNames, nationality, sex, birthDate, number, expiryDate, mrz }

    let kind: Kind
    let labelKey: String
    /// The text drawn on the page.
    let shown: String
    /// True when `shown` is a mask.
    let masked: Bool

    static let mask = String(repeating: "\u{2022}", count: 9)

    /// The rows of the page for `data`, the number and the MRZ masked unless `revealed`.
    static func rows(_ data: PassportData, revealed: Bool) -> [PassportRow] {
        func row(_ kind: Kind, _ key: String, _ value: String, secret: Bool = false) -> PassportRow {
            let masked = secret && !revealed && !value.isEmpty
            let shown: String
            if !masked {
                shown = value
            } else if kind == .mrz {
                // Two lines of bullets, the height of the real lines, nothing of their content.
                shown = String(repeating: "\u{2022}", count: 22) + "\n" + String(repeating: "\u{2022}", count: 22)
            } else {
                shown = mask
            }
            return PassportRow(kind: kind, labelKey: key, shown: shown, masked: masked)
        }
        return [
            row(.surname, "passport.surname", data.surname),
            row(.givenNames, "passport.givenNames", data.givenNames),
            row(.nationality, "passport.nationality", data.nationality),
            row(.sex, "passport.sex", data.sex),
            row(.birthDate, "passport.birthDate", data.birthDate),
            row(.number, "passport.number", data.number, secret: true),
            row(.expiryDate, "passport.expiryDate", data.expiryDate),
            row(.mrz, "passport.mrz", data.mrz, secret: true),
        ]
    }
}

struct DataPage: View, Animatable {
    let family: DocumentFamily
    let data: PassportData
    var revealProgress: Double
    let secretsRevealed: Bool

    nonisolated var animatableData: Double {
        get { revealProgress }
        set { revealProgress = newValue }
    }

    /// The page is laid out once at this size and scaled with the booklet (a physical object:
    /// its text follows the object, not Dynamic Type; VoiceOver reads every row).
    static let designSize = CGSize(width: 360, height: 360 / PassportFace.aspectRatio)

    static let photoFade = 0.30
    static let rowGap = 0.04
    static let rowFade = 0.18
    /// Reveal order of the rows after the portrait (the page's reading order, top to bottom).
    static let revealOrder: [PassportRow.Kind] = [.surname, .givenNames, .nationality, .sex, .birthDate, .number, .expiryDate, .mrz]
    static var revealDuration: Double { photoFade + Double(revealOrder.count - 1) * rowGap + rowFade }

    /// Opacity of the portrait at `progress`.
    static func photoOpacity(_ progress: Double) -> Double {
        clamp(progress * revealDuration / photoFade)
    }

    /// Opacity of the row at `index` in `revealOrder` at `progress`.
    static func rowOpacity(_ index: Int, _ progress: Double) -> Double {
        let t = progress * revealDuration - photoFade - Double(index) * rowGap
        return clamp(t / rowFade)
    }

    private static func clamp(_ v: Double) -> Double { min(max(v, 0), 1) }

    private var rows: [PassportRow] { PassportRow.rows(data, revealed: secretsRevealed) }

    private func row(_ kind: PassportRow.Kind) -> PassportRow? { rows.first { $0.kind == kind } }

    private func opacity(_ kind: PassportRow.Kind) -> Double {
        Self.rowOpacity(Self.revealOrder.firstIndex(of: kind) ?? 0, revealProgress)
    }

    private var ink: Color { Theme.RX.Document.pageInk.color }
    private var labelInk: Color { Theme.RX.Document.pageLabel.color }

    var body: some View {
        VStack(spacing: 0) {
            header
            HStack(alignment: .top, spacing: 14) {
                portrait
                    .frame(width: 84, height: 108)
                    .opacity(Self.photoOpacity(revealProgress))
                fields
            }
            .padding(.horizontal, 16)
            .padding(.top, 10)
            Spacer(minLength: 0)
            mrz
        }
        .background(Theme.RX.Document.page.color)
        .environment(\.dynamicTypeSize, .large)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("document.passport.page")
        #if os(iOS)
        .sensoryFeedback(.impact(weight: .light), trigger: revealProgress >= 1) { old, new in new && !old }
        #endif
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            HStack(spacing: 4) {
                Text(family.documentTitle, bundle: .module)
                if let country = family.countryTitle {
                    Text(verbatim: "·")
                    Text(country, bundle: .module)
                }
            }
            .font(.system(size: 8.5, weight: .semibold))
            .tracking(0.6)
            .textCase(.uppercase)
            .foregroundStyle(labelInk)
            .lineLimit(1)
            .minimumScaleFactor(0.5)
            .accessibilityHidden(true)
            Spacer(minLength: 8)
            // Always shown on the data page, never part of the reveal (spec section 4).
            Text("passport.notice", bundle: .module)
                .font(.system(size: 9, weight: .bold))
                .foregroundStyle(ink)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Theme.RX.Document.pageBand.color, in: Capsule())
                .accessibilityIdentifier("document.notice")
        }
        .padding(.horizontal, 16)
        .padding(.top, 12)
    }

    @ViewBuilder private var portrait: some View {
        if let image = data.portrait {
            image
                .resizable()
                .scaledToFill()
                .clipShape(.rect(cornerRadius: 4))
                .accessibilityLabel(Text("passport.portrait", bundle: .module))
        } else {
            RoundedRectangle(cornerRadius: 4)
                .fill(Theme.RX.Document.pageBand.color)
                .overlay {
                    Image(systemName: "person.fill")
                        .font(.system(size: 40))
                        .foregroundStyle(labelInk.opacity(0.5))
                }
                .accessibilityHidden(true)
        }
    }

    private var fields: some View {
        VStack(alignment: .leading, spacing: 6) {
            cell(.surname)
            cell(.givenNames)
            HStack(alignment: .top, spacing: 12) {
                cell(.nationality)
                cell(.sex)
            }
            HStack(alignment: .top, spacing: 12) {
                cell(.birthDate)
                cell(.expiryDate)
            }
            cell(.number)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder private func cell(_ kind: PassportRow.Kind) -> some View {
        if let row = row(kind) {
            VStack(alignment: .leading, spacing: 1) {
                Text(LocalizedStringKey(row.labelKey), bundle: .module)
                    .font(.system(size: 7.5, weight: .medium))
                    .foregroundStyle(labelInk)
                Text(verbatim: row.shown.isEmpty ? " " : row.shown)
                    .font(.system(size: 11.5, weight: .semibold, design: row.kind == .number ? .monospaced : .default))
                    .foregroundStyle(ink)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
            }
            .opacity(opacity(kind))
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text(LocalizedStringKey(row.labelKey), bundle: .module))
            .accessibilityValue(row.masked ? Text("fieldRow.hidden", bundle: .module) : Text(verbatim: row.shown))
            .accessibilityIdentifier("document.passport.\(kind)")
        }
    }

    @ViewBuilder private var mrz: some View {
        if let row = row(.mrz), !row.shown.isEmpty {
            Text(verbatim: row.shown)
                // A plain system monospace: never the OCR-B face of real documents.
                .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                .foregroundStyle(ink)
                .lineLimit(2)
                .minimumScaleFactor(0.5)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(Theme.RX.Document.pageBand.color)
                .opacity(opacity(.mrz))
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text("passport.mrz", bundle: .module))
                .accessibilityValue(row.masked ? Text("fieldRow.hidden", bundle: .module) : Text(verbatim: row.shown))
                .accessibilityIdentifier("document.passport.mrz")
        }
    }
}

// MARK: - List thumbnail

/// A closed passport for list rows: the cover tint, upright (88 x 125), with the chip symbol.
public struct PassportCoverThumbnail: View {
    private let family: DocumentFamily
    private let size: CGFloat

    /// `size` is the side of the square the thumbnail is centred in (an item row's icon size).
    public init(family: DocumentFamily, size: CGFloat) {
        self.family = family
        self.size = size
    }

    public var body: some View {
        let height = size
        let width = height * 88 / 125
        RoundedRectangle(cornerRadius: size * 0.1, style: .continuous)
            .fill(family.coverTint)
            .overlay(alignment: .leading) {
                LinearGradient(colors: [.black.opacity(0.3), .clear], startPoint: .leading, endPoint: .trailing)
                    .frame(width: width * 0.14)
            }
            .overlay(alignment: .bottom) {
                ChipSymbol()
                    .stroke(Theme.RX.Document.coverInk.color, lineWidth: max(size / 40, 0.8))
                    .frame(width: width * 0.42, height: width * 0.27)
                    .padding(.bottom, height * 0.14)
            }
            .clipShape(.rect(cornerRadius: size * 0.1, style: .continuous))
            .frame(width: width, height: height)
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}
