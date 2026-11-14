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
}
