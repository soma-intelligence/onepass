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

    /// 32 x 32 image in four quadrants, in order: top left, top right, bottom left, bottom right.
    private func quadrants(_ colors: [(Double, Double, Double)]) -> CGImage {
        let side = 32
        let context = CGContext(
            data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpace(name: CGColorSpace.sRGB)!,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        for (i, c) in colors.enumerated() {
            context.setFillColor(red: c.0, green: c.1, blue: c.2, alpha: 1)
            context.fill(CGRect(x: (i % 2) * 16, y: (i / 2) * 16, width: 16, height: 16))
        }
        return context.makeImage()!
    }

    @Test func transparentIconHasNoDominantColor() {
        #expect(IdentityTint.dominant(of: solidImage(side: 8, alpha: 0)) == nil)
        #expect(IdentityTint.dominant(of: solidImage(side: 1, rgb: (0, 0, 1))) != nil)
    }

    @Test func dominantOfASolidColorIsThatColor() throws {
        let dominant = try #require(IdentityTint.dominant(of: solidImage(side: 40, rgb: (1, 0, 0))))
        #expect(close(dominant, pureRed))
    }

    @Test func dominantIsTheBiggestHueBucketNotTheMean() throws {
        // Red, red, yellow, green: the mean would be olive, the dominant hue is red.
        let image = quadrants([(1, 0, 0), (1, 0, 0), (1, 1, 0), (0, 1, 0)])
        let dominant = try #require(IdentityTint.dominant(of: image))
        #expect(close(dominant, pureRed))
    }

    @Test func tieGoesToTheLowerBucket() throws {
        // Red (bucket 0), yellow (2), green (4), blue (8), one quadrant each: red wins.
        let image = quadrants([(0, 0, 1), (1, 1, 0), (0, 1, 0), (1, 0, 0)])
        let dominant = try #require(IdentityTint.dominant(of: image))
        #expect(close(dominant, pureRed))
    }

    @Test func grayBlackAndWhitePixelsDoNotCount() throws {
        #expect(IdentityTint.dominant(of: solidImage(side: 8, rgb: (0, 0, 0))) == nil)
        #expect(IdentityTint.dominant(of: solidImage(side: 8, rgb: (1, 1, 1))) == nil)
        #expect(IdentityTint.dominant(of: solidImage(side: 8, rgb: (0.5, 0.5, 0.5))) == nil)
        // Black ink around a small blue mark: the blue is the identity.
        let image = quadrants([(0, 0, 0), (0, 0, 0), (0, 0, 0), (0, 0, 1)])
        #expect(close(try #require(IdentityTint.dominant(of: image)), Color(.sRGB, red: 0, green: 0, blue: 1, opacity: 1)))
    }

    @Test func monochromeIconGivesTheAccent() {
        #expect(close(IdentityTint.color(brand: nil, siteIcon: solidImage(side: 8), category: .blue), Theme.accent))
        let gray = solidImage(side: 8, rgb: (0.5, 0.5, 0.5))
        #expect(close(IdentityTint.color(brand: nil, siteIcon: gray, category: .blue), Theme.accent))
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
