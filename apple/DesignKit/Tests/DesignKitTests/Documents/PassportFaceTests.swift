import ImageIO
import SwiftUI
import Testing
import UniformTypeIdentifiers

@testable import DesignKit

/// The passport booklet (spec 2026-11-21 sections 4 and 7). The image cells of the snapshot matrix
/// render on the iOS simulator only (`PassportFaceSnapshotTests` below); here, on any platform, the
/// same cells must render to a non-empty image, and the model behind the page is checked: family
/// per country, chip status per core label, masking, the notice and the reveal timing.
@MainActor
@Suite struct PassportFaceTests {
    /// Fictional holder (ICAO 9303 specimen style), never a real person.
    static let mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10"
    static let data = PassportData(
        surname: "Eriksson", givenNames: "Anna Maria", number: "L898902C3", nationality: "UTO",
        birthDate: "12 août 1974", expiryDate: "15 avr. 2032", sex: "F", mrz: mrz,
        portrait: nil, status: .verified, readOn: Date(timeIntervalSince1970: 1_795_219_200))

    // MARK: Family

    @Test func familyForCountry() {
        #expect(DocumentFamily.passport(issuingCountry: "FRA") == .passportFR)
        #expect(DocumentFamily.passport(issuingCountry: "USA") == .passportUS)
        #expect(DocumentFamily.passport(issuingCountry: "DEU") == .passportGeneric)
        #expect(DocumentFamily.passport(issuingCountry: " fra ") == .passportFR)
        #expect(DocumentFamily.passport(issuingCountry: "France") == .passportFR)
        #expect(DocumentFamily.passport(issuingCountry: "") == .passportGeneric)
        #expect(DocumentFamily.passportGeneric.countryKey == nil)
        #expect(DocumentFamily.passportFR.countryKey != nil && DocumentFamily.passportUS.countryKey != nil)
    }

    /// Each family has its own cover tint, in light and in dark.
    @Test func coverTintsDiffer() {
        let tokens = DocumentFamily.allCases.map(\.coverToken)
        #expect(Set(tokens.map { "\($0.light)" }).count == 3)
        #expect(Set(tokens.map { "\($0.dark)" }).count == 3)
    }

    /// The covers' text says what the object says: the French one in French and the US one in
    /// English in every language, the generic one in the app's language.
    @Test func coverTitles() {
        #expect(Self.string("document.passport.fr.title", "en") == "Passeport")
        #expect(Self.string("document.passport.fr.country", "en") == "République française")
        #expect(Self.string("document.passport.us.title", "fr") == "Passport")
        #expect(Self.string("document.passport.us.country", "fr") == "United States of America")
        #expect(Self.string("document.passport.title", "fr") == "Passeport")
        #expect(Self.string("document.passport.title", "en") == "Passport")
    }

    // MARK: Chip status

    @Test func chipStatusFromCoreLabels() {
        #expect(ChipBadge.Status(coreLabel: "Authentifié par la puce") == .verified)
        #expect(ChipBadge.Status(coreLabel: "Lu sur la puce, signature non vérifiable") == .unverifiable)
        #expect(ChipBadge.Status(coreLabel: "Signature invalide") == .invalid)
        #expect(ChipBadge.Status(coreLabel: "") == nil)
        #expect(ChipBadge.Status(coreLabel: "Saisie") == nil)
    }

    @Test func chipBadgeCopy() {
        let day = ChipBadge.day(Date(timeIntervalSince1970: 1_795_219_200), locale: Locale(identifier: "fr_FR"))
        #expect(day == "21 nov. 2026")
        let fr = Self.string("chipBadge.verified %@", "fr").replacingOccurrences(of: "%@", with: day)
        #expect(fr == "Authentifié par la puce le 21 nov. 2026")
        #expect(Self.string("chipBadge.help", "fr") == "Vérifie la signature de l'État, pas l'unicité de la puce.")
    }

    // MARK: Masking and notice

    /// Masked by default: neither the MRZ nor the number is in what the page draws or reads out.
    @Test func mrzMaskedByDefault() {
        let rows = PassportRow.rows(Self.data, revealed: false)
        let mrz = try! #require(rows.first { $0.kind == .mrz })
        let number = try! #require(rows.first { $0.kind == .number })
        #expect(mrz.masked && number.masked)
        for row in rows {
            #expect(!row.shown.contains("L898902C3"))
            #expect(!row.shown.contains("P<UTO"))
        }
        let shown = PassportRow.rows(Self.data, revealed: true)
        #expect(shown.first { $0.kind == .mrz }?.shown == Self.mrz)
        #expect(shown.first { $0.kind == .number }?.shown == "L898902C3")
        #expect(shown.allSatisfy { !$0.masked })
        // VoiceOver reads "masqué" for both, never the value.
        #expect(Self.string("fieldRow.hidden", "fr") == "masqué")
    }

    /// The notice is on the open data page in French and in English, whatever is revealed, and
    /// never part of the reveal.
    @Test func noticeAlwaysVisible() throws {
        #expect(Self.string("passport.notice", "fr") == "Copie numérique, non officielle")
        #expect(Self.string("passport.notice", "en") == "Digital copy, not an official document")
        // Drawn on the open page before anything is revealed and after: the notice capsule at
        // the right of the page's top band holds ink in both languages; the closed booklet hides it.
        let region = CGRect(x: 200, y: 6, width: 150, height: 22)
        for lang in ["fr", "en"] {
            for progress in [0.0, 1.0] {
                let open = face(.passportGeneric, open: true, progress: progress)
                    .environment(\.locale, Locale(identifier: lang))
                #expect(try Self.inkPixels(open, in: region) > 20, "\(lang) at \(progress)")
            }
            let closed = face(.passportGeneric, open: false).environment(\.locale, Locale(identifier: lang))
            let closedInk = try Self.inkPixels(closed, in: region)
            #expect(closedInk < 20)
        }
    }

    // MARK: Reveal

    @Test func revealOrderAndTiming() {
        #expect(DataPage.photoOpacity(0) == 0)
        #expect(DataPage.photoOpacity(1) == 1)
        for i in DataPage.revealOrder.indices {
            #expect(DataPage.rowOpacity(i, 0) == 0)
            #expect(DataPage.rowOpacity(i, 1) == 1)
        }
        // Rows start 40 ms apart, after the portrait.
        let duration = PassportFace.revealDuration
        func start(_ i: Int) -> Double {
            var p = 0.0
            while DataPage.rowOpacity(i, p) == 0, p < 1 { p += 0.0005 }
            return p * duration
        }
        #expect(abs(start(0) - DataPage.photoFade) < 0.002)
        #expect(abs((start(3) - start(2)) - 0.04) < 0.002)
    }

    // MARK: Rendering

    private func face(
        _ family: DocumentFamily, open: Bool, revealed: Bool = false, progress: Double = 1
    ) -> some View {
        PassportFace(family: family, data: Self.data, isOpen: .constant(open), revealProgress: progress,
                     secretsRevealed: revealed)
            .frame(width: 360)
    }

    /// Three families, closed and open, light and dark, French and English, Reduce Motion: each
    /// renders to a non-empty image of the TD3 proportions.
    @Test(arguments: DocumentFamily.allCases)
    func rendersEveryCell(_ family: DocumentFamily) throws {
        for open in [false, true] {
            for scheme in [ColorScheme.light, .dark] {
                for lang in ["fr", "en"] {
                    for reduce in [false, true] {
                        let view = face(family, open: open)
                            .environment(\.colorScheme, scheme)
                            .environment(\.locale, Locale(identifier: lang))
                            .environment(\.documentReduceMotion, reduce)
                        let renderer = ImageRenderer(content: view)
                        renderer.scale = 1
                        let image = try #require(renderer.cgImage)
                        Self.save(image, "passport-\(family)-\(open ? "open" : "closed")-\(scheme)-\(lang)\(reduce ? "-rm" : "")")
                        #expect(image.width == 360)
                        #expect(abs(Double(image.height) - 360 / PassportFace.aspectRatio) <= 1)
                    }
                }
            }
        }
    }

    @Test func badgeAndThumbnailRender() throws {
        for status in ChipBadge.Status.allCases {
            let renderer = ImageRenderer(content: ChipBadge(status: status, readOn: Date()).frame(width: 320))
            #expect(renderer.cgImage != nil)
        }
        let thumb = ImageRenderer(content: PassportCoverThumbnail(family: .passportFR, size: 40))
        let image = try #require(thumb.cgImage)
        #expect(image.width > 0)
    }

    // MARK: Helpers

    /// Writes `image` as a PNG into `ONEPASS_FEEDBACK_DIR` when it is set (looking at the cells by eye).
    static func save(_ image: CGImage, _ name: String) {
        guard let folder = ProcessInfo.processInfo.environment["ONEPASS_FEEDBACK_DIR"] else { return }
        let url = URL(fileURLWithPath: folder).appendingPathComponent("\(name).png")
        guard let out = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) else { return }
        CGImageDestinationAddImage(out, image, nil)
        CGImageDestinationFinalize(out)
    }

    static func string(_ key: String, _ lang: String) -> String {
        guard let path = Bundle.module.path(forResource: lang, ofType: "lproj"), let bundle = Bundle(path: path) else {
            return "<no \(lang)>"
        }
        return bundle.localizedString(forKey: key, value: "<missing>", table: nil)
    }

    /// Dark ink pixels in `region` (design points, scale 1) of the open page rendered 360 pt wide.
    static func inkPixels(_ view: some View, in region: CGRect) throws -> Int {
        let renderer = ImageRenderer(content: view)
        renderer.scale = 1
        let image = try #require(renderer.cgImage)
        let width = image.width, height = image.height
        var pixels = [UInt8](repeating: 0, count: width * height * 4)
        let context = try #require(CGContext(
            data: &pixels, width: width, height: height, bitsPerComponent: 8, bytesPerRow: width * 4,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
        var count = 0
        for y in Int(region.minY)..<min(Int(region.maxY), height) {
            for x in Int(region.minX)..<min(Int(region.maxX), width) {
                let i = (y * width + x) * 4
                let luminance = (Int(pixels[i]) + Int(pixels[i + 1]) + Int(pixels[i + 2])) / 3
                if pixels[i + 3] > 200, luminance < 50 { count += 1 }
            }
        }
        return count
    }
}

#if os(iOS)
import DesignBridgeSnapshots
import SnapshotTesting

/// The image cells of the booklet on the DesignBridge matrix (iPhone 17 Pro, light and dark,
/// French and English): the three families closed and open, and Reduce Motion. iOS simulator
/// only (`xcodebuild test -scheme DesignKit`); a missing reference is recorded on the first run.
@MainActor
@Suite(.snapshots(record: .missing))
struct PassportFaceSnapshotTests {
    private static let matrix = SnapshotMatrix.smoke
        .with(contentSizes: [.large])
        .with(locales: [.fr, .en])

    private func page(_ family: DocumentFamily, open: Bool, reduceMotion: Bool = false) -> some View {
        VStack(spacing: Theme.RX.Space.l) {
            PassportFace(family: family, data: PassportFaceTests.data, isOpen: .constant(open), secretsRevealed: false)
            ChipBadge(status: .verified, readOn: PassportFaceTests.data.readOn!)
        }
        .padding(Theme.RX.Space.l)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(Theme.RX.Palette.pageBackground.color)
        .environment(\.documentReduceMotion, reduceMotion)
    }

    @Test(arguments: DocumentFamily.allCases)
    func closed(_ family: DocumentFamily) {
        snapshotMatrix(of: { _ in page(family, open: false) }, name: "passport-\(family)-closed", matrix: Self.matrix)
    }

    @Test(arguments: DocumentFamily.allCases)
    func open(_ family: DocumentFamily) {
        snapshotMatrix(of: { _ in page(family, open: true) }, name: "passport-\(family)-open", matrix: Self.matrix)
    }

    @Test func reduceMotion() {
        snapshotMatrix(of: { _ in page(.passportFR, open: true, reduceMotion: true) },
                       name: "passport-reduceMotion", matrix: Self.matrix)
    }
}
#endif
