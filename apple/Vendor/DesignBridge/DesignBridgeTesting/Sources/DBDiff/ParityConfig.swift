import CoreGraphics
import Foundation

/// Thresholds read from `design/parity.json`, or from the `parity` key of `designbridge.json`.
///
/// ```json
/// {
///   "ssim": 0.97,
///   "maxOffsetPt": 1,
///   "scale": 3,
///   "masks": [[0, 0, 402, 54]],
///   "overrides": { "RX/Menu row": { "ssim": 0.95 } }
/// }
/// ```
public struct ParityConfig: Codable, Sendable, Equatable {
    public struct Threshold: Codable, Sendable, Equatable {
        public var ssim: Double?
        public var maxOffsetPt: Double?
        /// Rectangles in points as `[x, y, width, height]`.
        public var masks: [[Double]]?

        public init(ssim: Double? = nil, maxOffsetPt: Double? = nil, masks: [[Double]]? = nil) {
            self.ssim = ssim
            self.maxOffsetPt = maxOffsetPt
            self.masks = masks
        }
    }

    public var ssim: Double?
    public var maxOffsetPt: Double?
    public var scale: Double?
    public var masks: [[Double]]?
    public var overrides: [String: Threshold]?

    public init(
        ssim: Double? = nil,
        maxOffsetPt: Double? = nil,
        scale: Double? = nil,
        masks: [[Double]]? = nil,
        overrides: [String: Threshold]? = nil
    ) {
        self.ssim = ssim
        self.maxOffsetPt = maxOffsetPt
        self.scale = scale
        self.masks = masks
        self.overrides = overrides
    }

    private struct Wrapper: Decodable { var parity: ParityConfig? }

    /// Accepts either a bare parity object or a whole `designbridge.json`.
    public static func decode(_ data: Data) throws -> ParityConfig {
        let decoder = JSONDecoder()
        if let wrapped = try? decoder.decode(Wrapper.self, from: data), let parity = wrapped.parity {
            return parity
        }
        do {
            return try decoder.decode(ParityConfig.self, from: data)
        } catch {
            throw DBDiffError.config("cannot decode parity config: \(error)")
        }
    }

    public static func load(_ url: URL) throws -> ParityConfig {
        try decode(Data(contentsOf: url))
    }

    /// Options for the comparison named `name`, layered as defaults, then this file, then the
    /// override whose key matches `name`, then `base` values the caller set explicitly.
    public func options(for name: String, base: ComparisonOptions = .init()) throws -> ComparisonOptions {
        var o = base
        if let ssim { o.ssimThreshold = ssim }
        if let maxOffsetPt { o.maxOffsetPoints = maxOffsetPt }
        if let scale { o.scale = scale }
        if let masks { o.masks += try Self.rects(masks) }
        if let t = overrides?[name] {
            if let s = t.ssim { o.ssimThreshold = s }
            if let m = t.maxOffsetPt { o.maxOffsetPoints = m }
            if let masks = t.masks { o.masks += try Self.rects(masks) }
        }
        return o
    }

    static func rects(_ raw: [[Double]]) throws -> [CGRect] {
        try raw.map {
            guard $0.count == 4 else { throw DBDiffError.config("a mask needs [x, y, width, height], got \($0)") }
            return CGRect(x: $0[0], y: $0[1], width: $0[2], height: $0[3])
        }
    }
}
