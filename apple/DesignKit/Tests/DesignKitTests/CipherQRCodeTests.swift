import CoreImage
import ImageIO
import SwiftUI
import Testing
import UniformTypeIdentifiers

@testable import DesignKit

@Suite struct CipherQRCodeTests {
    /// A pairing text the size of the real ones (prefix, then about 120 characters of base64url).
    static let text = "OPPAIR1:" + String(repeating: "q7Zk-3VxA_9bTm2LpR5w", count: 6)

    @Test func matrixIsASquareWithItsThreeFinders() throws {
        let matrix = try #require(QRMatrix(text: Self.text))
        #expect(matrix.side >= 21 && (matrix.side - 17) % 4 == 0)
        for (x, y) in [(0, 0), (matrix.side - 7, 0), (0, matrix.side - 7)] {
            // A finder: dark ring, light ring, dark 3 x 3 core.
            #expect(matrix.isDark(x, y) && matrix.isDark(x + 6, y + 6))
            #expect(!matrix.isDark(x + 1, y + 1) && !matrix.isDark(x + 5, y + 5))
            #expect(matrix.isDark(x + 3, y + 3))
            #expect(matrix.isFinder(x + 3, y + 3))
        }
        #expect(!matrix.isFinder(matrix.side - 1, matrix.side - 1))
    }

    /// The tile as drawn (round dots, rounded eyes, the mark over the middle, the ring) still reads
    /// with a QR detector, at the size it has on a Mac (260 pt) and smaller.
    @MainActor @Test(arguments: [260.0, 200.0]) func drawnCodeStillScans(side: Double) throws {
        let view = CipherQRCode(stage: .code(Self.text), expiresAt: Date().addingTimeInterval(20), animated: false)
            .frame(width: side, height: side)
            .padding(24)
            .background(Color(white: 0.11))
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2
        let image = try #require(renderer.cgImage)
        if let folder = ProcessInfo.processInfo.environment["ONEPASS_FEEDBACK_DIR"] {
            let url = URL(fileURLWithPath: folder).appendingPathComponent("cipher-qr-\(Int(side)).png")
            if let out = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) {
                CGImageDestinationAddImage(out, image, nil)
                CGImageDestinationFinalize(out)
            }
        }
        let detector = try #require(CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
        let found = detector.features(in: CIImage(cgImage: image)).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
        #expect(found == [Self.text])
    }

    /// Standing still, every dot is whole and no cipher shows; once the wave has passed, nothing of
    /// the QR is left.
    @Test func waveEndsCleanly() {
        typealias Frame = CipherQRCode.Frame
        for d in [0.0, 0.5, 1.0] {
            let idle = CipherQRCode.cell(Frame(appear: 10, dissolve: nil, settle: nil, code: nil, scrambles: true), distance: d)
            #expect(abs(idle.dot - 1) < 0.001 && idle.glyph == 0)
            let gone = CipherQRCode.cell(Frame(appear: 10, dissolve: 5, settle: nil, code: nil, scrambles: true), distance: d)
            #expect(gone.dot == 0 && gone.glyph == 0)
            let start = CipherQRCode.cell(Frame(appear: 0, dissolve: nil, settle: nil, code: nil, scrambles: true), distance: d)
            #expect(start.dot == 0)
        }
        // The still drawings never show a scrambling character.
        let still = CipherQRCode.cell(Frame(appear: 0.3, dissolve: nil, settle: nil, code: nil, scrambles: false), distance: 0.2)
        #expect(still.glyph == 0)
    }

    /// The animation as a strip of real frames (appearance, then connection and the code), to
    /// `ONEPASS_FEEDBACK_DIR/cipher-qr-strip.png` (captures only).
    @MainActor @Test func strip() throws {
        guard let folder = ProcessInfo.processInfo.environment["ONEPASS_FEEDBACK_DIR"] else { return }
        typealias Frame = CipherQRCode.Frame
        let appear = [0.1, 0.3, 0.5, 0.75, 1.3].map { Frame(appear: $0, dissolve: nil, settle: nil, code: nil, scrambles: true) }
        let connect = [0.15, 0.4, 0.7, 1.0].map { Frame(appear: 10, dissolve: $0, settle: nil, code: nil, scrambles: true) }
            + [0.2, 0.5, 1.2].map { Frame(appear: 10, dissolve: 1.4 + $0, settle: $0, code: "482913", scrambles: true) }
        func row(_ frames: [Frame]) -> some View {
            HStack(spacing: 14) {
                ForEach(Array(frames.enumerated()), id: \.offset) { _, frame in
                    Canvas { context, size in
                        var context = context
                        CipherQRCode.draw(&context, size: size, matrix: QRMatrix.cached(Self.text), frame: frame)
                    }
                    .frame(width: 220, height: 220)
                    .background(Color.white, in: RoundedRectangle(cornerRadius: 19, style: .continuous))
                }
            }
        }
        let view = VStack(alignment: .leading, spacing: 14) { row(appear); row(connect) }
            .padding(20)
            .background(Color(white: 0.11))
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2
        let image = try #require(renderer.cgImage)
        let url = URL(fileURLWithPath: folder).appendingPathComponent("cipher-qr-strip.png")
        let out = try #require(CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil))
        CGImageDestinationAddImage(out, image, nil)
        #expect(CGImageDestinationFinalize(out))
    }
}
