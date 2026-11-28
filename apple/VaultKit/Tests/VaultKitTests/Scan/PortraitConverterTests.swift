import CoreGraphics
import Foundation
import ImageIO
import OnePassCore
import Testing
import UniformTypeIdentifiers

@testable import VaultKit

@Suite struct PortraitConverterTests {
    /// A small grey gradient encoded with ImageIO in the given format.
    static func image(_ type: UTType) throws -> Data {
        let (w, h) = (24, 32)
        var pixels = [UInt8](repeating: 0, count: w * h)
        for i in pixels.indices { pixels[i] = UInt8(truncatingIfNeeded: i) }
        let ctx = try #require(
            CGContext(
                data: &pixels, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w,
                space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue))
        let cg = try #require(ctx.makeImage())
        let out = NSMutableData()
        let dest = try #require(CGImageDestinationCreateWithData(out, type.identifier as CFString, 1, nil))
        CGImageDestinationAddImage(dest, cg, nil)
        #expect(CGImageDestinationFinalize(dest))
        return out as Data
    }

    @Test func jp2ToJpeg() throws {
        let jp2 = try Self.image(UTType("public.jpeg-2000")!)
        #expect(jp2.prefix(2) != Data([0xFF, 0xD8]))
        let jpeg = try PortraitConverter.jpeg(from: jp2, format: .jpeg2000)
        #expect(jpeg.prefix(2) == Data([0xFF, 0xD8]))
    }

    @Test func jpegKeptAsIs() throws {
        let jpeg = try Self.image(.jpeg)
        #expect(try PortraitConverter.jpeg(from: jpeg, format: .jpeg) == jpeg)
    }

    @Test func garbageThrows() {
        #expect(throws: PortraitConverter.ConversionError.undecodable) {
            try PortraitConverter.jpeg(from: Data([1, 2, 3, 4]), format: .jpeg2000)
        }
    }
}
