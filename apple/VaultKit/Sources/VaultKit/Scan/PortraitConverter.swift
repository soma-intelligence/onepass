import Foundation
import ImageIO
import OnePassCore
import UniformTypeIdentifiers

/// The DG2 portrait as a JPEG the app can show and attach: a JPEG is kept as the chip stores it,
/// a JPEG 2000 is decoded and encoded again (quality 0.9).
public enum PortraitConverter {
    public enum ConversionError: Error, Sendable, Equatable {
        case undecodable
        case unencodable
    }

    public static func jpeg(from data: Data, format: FfiImageFormat) throws -> Data {
        if format == .jpeg { return data }
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
            let image = CGImageSourceCreateImageAtIndex(source, 0, nil)
        else { throw ConversionError.undecodable }
        let out = NSMutableData()
        guard
            let dest = CGImageDestinationCreateWithData(
                out, UTType.jpeg.identifier as CFString, 1, nil)
        else { throw ConversionError.unencodable }
        CGImageDestinationAddImage(
            dest, image, [kCGImageDestinationLossyCompressionQuality: 0.9] as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { throw ConversionError.unencodable }
        return out as Data
    }
}
