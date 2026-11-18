import CoreGraphics
import Foundation
import ImageIO

/// An opaque 8-bit RGBA bitmap, row major, 4 bytes per pixel, alpha always 255.
///
/// Images are flattened over a background when loaded so that transparent Penpot exports
/// and opaque simulator screenshots compare on equal terms.
public struct RGBAImage: Equatable, Sendable {
    public let width: Int
    public let height: Int
    public var pixels: [UInt8]

    public init(width: Int, height: Int, pixels: [UInt8]) {
        precondition(width > 0 && height > 0, "Image dimensions must be positive")
        precondition(pixels.count == width * height * 4, "Pixel buffer does not match dimensions")
        self.width = width
        self.height = height
        self.pixels = pixels
    }

    /// A solid image.
    public init(width: Int, height: Int, fill: RGBA) {
        var buffer = [UInt8](repeating: 0, count: width * height * 4)
        for i in 0..<(width * height) {
            buffer[i * 4] = fill.r
            buffer[i * 4 + 1] = fill.g
            buffer[i * 4 + 2] = fill.b
            buffer[i * 4 + 3] = 255
        }
        self.init(width: width, height: height, pixels: buffer)
    }

    public var size: CGSize { CGSize(width: width, height: height) }

    public subscript(x: Int, y: Int) -> RGBA {
        get {
            let i = (y * width + x) * 4
            return RGBA(pixels[i], pixels[i + 1], pixels[i + 2])
        }
        set {
            let i = (y * width + x) * 4
            pixels[i] = newValue.r
            pixels[i + 1] = newValue.g
            pixels[i + 2] = newValue.b
            pixels[i + 3] = 255
        }
    }

    /// Rec. 709 luma in 0...255, one value per pixel.
    public func luma() -> [Float] {
        var out = [Float](repeating: 0, count: width * height)
        pixels.withUnsafeBufferPointer { p in
            for i in 0..<(width * height) {
                let r = Float(p[i * 4]), g = Float(p[i * 4 + 1]), b = Float(p[i * 4 + 2])
                out[i] = 0.2126 * r + 0.7152 * g + 0.0722 * b
            }
        }
        return out
    }

    // MARK: Core Graphics bridge

    /// Draws `cgImage` into a new bitmap of `size` (defaults to the image size), over `background`.
    public init(cgImage: CGImage, size: CGSize? = nil, background: RGBA = .white) throws {
        let w = Int(size?.width ?? CGFloat(cgImage.width))
        let h = Int(size?.height ?? CGFloat(cgImage.height))
        guard w > 0, h > 0 else { throw DBDiffError.invalidImage("empty image") }
        var buffer = [UInt8](repeating: 0, count: w * h * 4)
        let drawn: Bool = buffer.withUnsafeMutableBytes { raw in
            guard let ctx = CGContext(
                data: raw.baseAddress,
                width: w,
                height: h,
                bitsPerComponent: 8,
                bytesPerRow: w * 4,
                space: CGColorSpace(name: CGColorSpace.sRGB)!,
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
            ) else { return false }
            ctx.interpolationQuality = .high
            ctx.setFillColor(
                CGColor(
                    srgbRed: CGFloat(background.r) / 255,
                    green: CGFloat(background.g) / 255,
                    blue: CGFloat(background.b) / 255,
                    alpha: 1
                )
            )
            ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
            ctx.draw(cgImage, in: CGRect(x: 0, y: 0, width: w, height: h))
            return true
        }
        guard drawn else { throw DBDiffError.invalidImage("cannot create bitmap context") }
        self.init(width: w, height: h, pixels: buffer)
    }

    /// Loads a PNG (or any ImageIO format) from disk.
    public init(contentsOf url: URL, size: CGSize? = nil, background: RGBA = .white) throws {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
              let image = CGImageSourceCreateImageAtIndex(source, 0, nil)
        else { throw DBDiffError.invalidImage("cannot read \(url.path)") }
        try self.init(cgImage: image, size: size, background: background)
    }

    public func cgImage() -> CGImage {
        let data = Data(pixels) as CFData
        let provider = CGDataProvider(data: data)!
        return CGImage(
            width: width,
            height: height,
            bitsPerComponent: 8,
            bitsPerPixel: 32,
            bytesPerRow: width * 4,
            space: CGColorSpace(name: CGColorSpace.sRGB)!,
            bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.noneSkipLast.rawValue),
            provider: provider,
            decode: nil,
            shouldInterpolate: false,
            intent: .defaultIntent
        )!
    }

    /// Resamples to `size` with Core Graphics high quality interpolation.
    public func resized(to size: CGSize) throws -> RGBAImage {
        if Int(size.width) == width, Int(size.height) == height { return self }
        return try RGBAImage(cgImage: cgImage(), size: size)
    }

    public func pngData() throws -> Data {
        let data = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(data as CFMutableData, "public.png" as CFString, 1, nil)
        else { throw DBDiffError.io("cannot create PNG encoder") }
        CGImageDestinationAddImage(dest, cgImage(), nil)
        guard CGImageDestinationFinalize(dest) else { throw DBDiffError.io("cannot encode PNG") }
        return data as Data
    }

    public func writePNG(to url: URL) throws {
        try pngData().write(to: url, options: .atomic)
    }
}

public struct RGBA: Equatable, Hashable, Sendable {
    public var r: UInt8
    public var g: UInt8
    public var b: UInt8

    public init(_ r: UInt8, _ g: UInt8, _ b: UInt8) {
        self.r = r
        self.g = g
        self.b = b
    }

    public static let white = RGBA(255, 255, 255)
    public static let black = RGBA(0, 0, 0)
}

public enum DBDiffError: Error, CustomStringConvertible, Equatable {
    case invalidImage(String)
    case io(String)
    case config(String)

    public var description: String {
        switch self {
        case .invalidImage(let m): "invalid image: \(m)"
        case .io(let m): "io: \(m)"
        case .config(let m): "config: \(m)"
        }
    }
}
