import CoreGraphics
import Foundation
import ImageIO
import Testing
import UniformTypeIdentifiers

@testable import VaultKit

@Suite struct ItemIconResolverGateTests {
    /// An opaque PNG of the given size.
    private func png(_ width: Int, _ height: Int) -> Data {
        let context = CGContext(
            data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
        context.setFillColor(CGColor(red: 0.2, green: 0.5, blue: 0.8, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let data = NSMutableData()
        let destination = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(destination, context.makeImage()!, nil)
        CGImageDestinationFinalize(destination)
        return data as Data
    }

    // The loader stores min(256, 2 x source) pixels; each PNG here is the stored size of the source in the name.
    @Test func refusesSource31() { #expect(ItemIconResolver.sharpEnough(png(62, 62)) == nil) }
    @Test func keepsSource32() { #expect(ItemIconResolver.sharpEnough(png(64, 64)) != nil) }
    @Test func keepsWideSource32x16() { #expect(ItemIconResolver.sharpEnough(png(64, 32)) != nil) }
    @Test func keepsSource128() { #expect(ItemIconResolver.sharpEnough(png(256, 256)) != nil) }
}
