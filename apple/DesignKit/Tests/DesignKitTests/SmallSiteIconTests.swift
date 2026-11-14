import CoreGraphics
import Testing

@testable import DesignKit

@Suite struct SmallSiteIconTests {
    private func image(_ width: Int, _ height: Int) -> CGImage {
        let context = CGContext(
            data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
        return context.makeImage()!
    }

    /// A 32x16 site icon is drawn at its own size in a 38 pt tile, not stretched.
    @Test func smallIconTakesTheBareBranch() {
        #expect(ItemIcon.isLowResolution(image(32, 16), side: 38))
    }

    @Test func sharpIconFillsTheTile() {
        #expect(!ItemIcon.isLowResolution(image(256, 256), side: 38))
    }

    /// A stored 64 px icon (a 32 px source) in a 38 pt row is drawn bare: a 3x screen needs 114 px.
    @Test func storedSixtyFourIsLowResolution() {
        #expect(ItemIcon.isLowResolution(image(64, 64), side: 38))
    }

    /// The boundary: 114 px fills a 38 pt tile on a 3x screen, 113 px does not.
    @Test func boundaryIsThreeTimesTheSide() {
        #expect(!ItemIcon.isLowResolution(image(114, 114), side: 38))
        #expect(ItemIcon.isLowResolution(image(113, 113), side: 38))
        #expect(ItemIcon.isLowResolution(image(200, 113), side: 38))
    }
}
