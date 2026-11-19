import CoreGraphics
import Foundation

/// Thresholds and knobs for one comparison.
public struct ComparisonOptions: Sendable, Equatable {
    /// Minimum SSIM to pass. The spec default is 0.97.
    public var ssimThreshold: Double
    /// Largest layout offset tolerated, in points. The spec default is 1 pt.
    public var maxOffsetPoints: Double
    /// Pixels per point of both images (Penpot exports at @3x).
    public var scale: Double
    /// Regions ignored in both images, in points (status bar, live clock, avatars).
    public var masks: [CGRect]
    /// Resample the candidate to the reference size when the aspect ratios match within 1%.
    public var resizeCandidate: Bool
    /// Per-channel difference (0...255) under which a pixel counts as unchanged in the diff image.
    public var pixelTolerance: UInt8
    /// RGB (default) or luma SSIM.
    public var colorMode: SSIM.ColorMode
    public var window: Int
    public var stride: Int

    public init(
        ssimThreshold: Double = 0.97,
        maxOffsetPoints: Double = 1,
        scale: Double = 3,
        masks: [CGRect] = [],
        resizeCandidate: Bool = true,
        pixelTolerance: UInt8 = 8,
        colorMode: SSIM.ColorMode = .rgb,
        window: Int = 8,
        stride: Int = 4
    ) {
        self.ssimThreshold = ssimThreshold
        self.maxOffsetPoints = maxOffsetPoints
        self.scale = scale
        self.masks = masks
        self.resizeCandidate = resizeCandidate
        self.pixelTolerance = pixelTolerance
        self.colorMode = colorMode
        self.window = window
        self.stride = stride
    }

    /// The offset search radius in pixels.
    public var maxShiftPixels: Int { max(0, Int((maxOffsetPoints * scale).rounded(.down))) }
}

public struct ComparisonResult: Sendable {
    public var name: String
    /// SSIM at the best offset within tolerance (the score that is gated).
    public var ssim: Double
    /// SSIM with no shift, reported so a pure offset problem is visible.
    public var ssimAtZeroOffset: Double
    /// Best alignment, in pixels.
    public var offset: OffsetSearch.Offset
    public var offsetPoints: Double
    /// Share of compared pixels whose difference exceeds `pixelTolerance`.
    public var changedPixelRatio: Double
    /// Bounding box of changed pixels in reference pixel coordinates, nil when nothing changed.
    public var changedBounds: CGRect?
    public var passed: Bool
    public var failures: [String]
    public var thresholds: ComparisonOptions
    public var diffImage: RGBAImage
    public var candidateWasResized: Bool
}

public enum ImageComparator {
    public static func compare(
        reference: RGBAImage,
        candidate: RGBAImage,
        name: String = "",
        options: ComparisonOptions = .init()
    ) throws -> ComparisonResult {
        var cand = candidate
        var resized = false
        if cand.width != reference.width || cand.height != reference.height {
            let refAspect = Double(reference.width) / Double(reference.height)
            let candAspect = Double(cand.width) / Double(cand.height)
            guard options.resizeCandidate, abs(refAspect - candAspect) / refAspect <= 0.01 else {
                throw DBDiffError.invalidImage(
                    "size mismatch for \(name): reference \(reference.width)x\(reference.height), "
                        + "candidate \(cand.width)x\(cand.height)"
                )
            }
            cand = try cand.resized(to: reference.size)
            resized = true
        }

        var ref = reference
        applyMasks(options.masks, scale: options.scale, reference: &ref, candidate: &cand)

        // Alignment is searched on luma, which is enough to find a layout shift.
        let shift = OffsetSearch.best(reference: Plane(ref), candidate: Plane(cand), maxShift: options.maxShiftPixels)
        let atZero = SSIM.compute(ref, cand, mode: options.colorMode, window: options.window, stride: options.stride)
        var offset = OffsetSearch.Offset.zero
        var score = atZero
        if shift != .zero {
            let shifted = SSIM.compute(ref, cand, offset: shift, mode: options.colorMode, window: options.window, stride: options.stride)
            if shifted > score {
                score = shifted
                offset = shift
            }
        }

        let diff = diffImage(reference: ref, candidate: cand, offset: offset, tolerance: options.pixelTolerance)
        let offsetPoints = offset.magnitude / options.scale

        var failures: [String] = []
        if score < options.ssimThreshold {
            failures.append(String(format: "SSIM %.4f is below %.4f", score, options.ssimThreshold))
        }
        if offsetPoints > options.maxOffsetPoints + 1e-9 {
            failures.append(String(format: "offset %.2f pt exceeds %.2f pt", offsetPoints, options.maxOffsetPoints))
        }

        return ComparisonResult(
            name: name,
            ssim: score,
            ssimAtZeroOffset: atZero,
            offset: offset,
            offsetPoints: offsetPoints,
            changedPixelRatio: diff.ratio,
            changedBounds: diff.bounds,
            passed: failures.isEmpty,
            failures: failures,
            thresholds: options,
            diffImage: diff.image,
            candidateWasResized: resized
        )
    }

    /// Paints masked regions grey in both images so they never count.
    static func applyMasks(_ masks: [CGRect], scale: Double, reference: inout RGBAImage, candidate: inout RGBAImage) {
        let grey = RGBA(128, 128, 128)
        for m in masks {
            let x0 = max(0, Int((m.minX * scale).rounded(.down)))
            let y0 = max(0, Int((m.minY * scale).rounded(.down)))
            let x1 = min(reference.width, Int((m.maxX * scale).rounded(.up)))
            let y1 = min(reference.height, Int((m.maxY * scale).rounded(.up)))
            guard x1 > x0, y1 > y0 else { continue }
            for y in y0..<y1 {
                for x in x0..<x1 {
                    reference[x, y] = grey
                    candidate[x, y] = grey
                }
            }
        }
    }

    /// A heat map: the reference washed out to light grey, changed pixels in red with an opacity
    /// that grows with the difference. Pixels outside the overlap are drawn in blue.
    public static func diffImage(
        reference: RGBAImage,
        candidate: RGBAImage,
        offset: OffsetSearch.Offset,
        tolerance: UInt8
    ) -> (image: RGBAImage, ratio: Double, bounds: CGRect?) {
        let w = reference.width, h = reference.height
        var out = [UInt8](repeating: 255, count: w * h * 4)
        var changed = 0, compared = 0
        var minX = Int.max, minY = Int.max, maxX = -1, maxY = -1

        reference.pixels.withUnsafeBufferPointer { r in
            candidate.pixels.withUnsafeBufferPointer { c in
                for y in 0..<h {
                    for x in 0..<w {
                        let i = (y * w + x) * 4
                        let luma = 0.2126 * Double(r[i]) + 0.7152 * Double(r[i + 1]) + 0.0722 * Double(r[i + 2])
                        let base = 200 + luma * 55 / 255
                        let cx = x + offset.dx, cy = y + offset.dy
                        guard cx >= 0, cy >= 0, cx < w, cy < h else {
                            out[i] = 120; out[i + 1] = 160; out[i + 2] = 230
                            continue
                        }
                        compared += 1
                        let j = (cy * w + cx) * 4
                        let d = max(
                            absDiff(r[i], c[j]),
                            absDiff(r[i + 1], c[j + 1]),
                            absDiff(r[i + 2], c[j + 2])
                        )
                        if d > tolerance {
                            changed += 1
                            minX = min(minX, x); minY = min(minY, y)
                            maxX = max(maxX, x); maxY = max(maxY, y)
                            let alpha = 0.35 + 0.65 * Double(d) / 255
                            out[i] = UInt8(base * (1 - alpha) + 230 * alpha)
                            out[i + 1] = UInt8(base * (1 - alpha) + 20 * alpha)
                            out[i + 2] = UInt8(base * (1 - alpha) + 40 * alpha)
                        } else {
                            let v = UInt8(base)
                            out[i] = v; out[i + 1] = v; out[i + 2] = v
                        }
                    }
                }
            }
        }
        let bounds: CGRect? = maxX < 0 ? nil : CGRect(x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1)
        return (RGBAImage(width: w, height: h, pixels: out), Double(changed) / Double(max(1, compared)), bounds)
    }

    @inline(__always)
    static func absDiff(_ a: UInt8, _ b: UInt8) -> UInt8 { a > b ? a - b : b - a }
}
