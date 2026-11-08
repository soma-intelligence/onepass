import CoreGraphics
import SwiftUI
import Testing

@testable import DesignKit

@Suite("IdentityTint")
struct IdentityTintTests {
    private func close(_ a: Color, _ b: Color) -> Bool {
        let env = EnvironmentValues()
        let x = a.resolve(in: env)
        let y = b.resolve(in: env)
        let tolerance: Float = 0.01
        return abs(x.red - y.red) < tolerance && abs(x.green - y.green) < tolerance
            && abs(x.blue - y.blue) < tolerance && abs(x.opacity - y.opacity) < tolerance
    }

    /// A square image filled with one color, drawn in an sRGB context.
    private func solidImage(side: Int, rgb: (Double, Double, Double) = (0, 0, 0), alpha: Double = 1) -> CGImage {
        let context = CGContext(
            data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpace(name: CGColorSpace.sRGB)!,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        context.setFillColor(red: rgb.0, green: rgb.1, blue: rgb.2, alpha: alpha)
        context.fill(CGRect(x: 0, y: 0, width: side, height: side))
        return context.makeImage()!
    }

    /// Pure sRGB red: `Color.red` is the system red (#FF383C), not the (1, 0, 0) the test images use.
    private let pureRed = Color(.sRGB, red: 1, green: 0, blue: 0, opacity: 1)

    @Test func grayFallsBackToAccent() {
        #expect(close(IdentityTint.fallback(.black), Theme.accent))
        #expect(close(IdentityTint.fallback(Color(white: 0.5)), Theme.accent))
        #expect(close(IdentityTint.fallback(.orange), .orange))
    }

    @Test func transparentIconHasNoAverage() {
        #expect(IdentityTint.average(of: solidImage(side: 8, alpha: 0)) == nil)
        #expect(IdentityTint.average(of: solidImage(side: 1, rgb: (0, 0, 1))) != nil)
    }

    @Test func averageIsTheMeanColor() throws {
        let average = try #require(IdentityTint.average(of: solidImage(side: 40, rgb: (1, 0, 0))))
        #expect(close(average, pureRed))
    }

    @Test func order() {
        let c = IdentityTint.color(brand: nil, siteIcon: solidImage(side: 4, rgb: (1, 0, 0)), category: .blue)
        #expect(close(c, pureRed))
        #expect(close(IdentityTint.color(brand: nil, siteIcon: nil, category: .blue), .blue))
        #expect(close(IdentityTint.color(brand: "amex", siteIcon: solidImage(side: 4, rgb: (1, 0, 0)), category: .blue),
                      Color(red: 0x2E / 255, green: 0x77 / 255, blue: 0xBC / 255)))
    }

    @Test func darkOpacityCap() {
        // Review Focus 5: the wash never passes 22% so titles stay readable.
        #expect(Theme.Wash.identityOpacity(dark: true) == 0.22)
        #expect(Theme.Wash.identityOpacity(dark: false) == 0.14)
    }
}
