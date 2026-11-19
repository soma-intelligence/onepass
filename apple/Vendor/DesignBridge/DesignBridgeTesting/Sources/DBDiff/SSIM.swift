import Foundation

/// A single-channel plane of values in 0...255 (luma, or one colour channel).
public struct Plane: Sendable, Equatable {
    public let width: Int
    public let height: Int
    public var values: [Float]

    public init(width: Int, height: Int, values: [Float]) {
        precondition(values.count == width * height, "Plane size mismatch")
        self.width = width
        self.height = height
        self.values = values
    }

    /// Rec. 709 luma of `image`.
    public init(_ image: RGBAImage) {
        self.init(width: image.width, height: image.height, values: image.luma())
    }

    /// One channel of `image`: 0 red, 1 green, 2 blue.
    public init(_ image: RGBAImage, channel: Int) {
        precondition((0...2).contains(channel), "channel must be 0, 1 or 2")
        var out = [Float](repeating: 0, count: image.width * image.height)
        image.pixels.withUnsafeBufferPointer { p in
            for i in 0..<out.count { out[i] = Float(p[i * 4 + channel]) }
        }
        self.init(width: image.width, height: image.height, values: out)
    }

    /// Copies the rectangle starting at (`x`, `y`) of size `w` x `h`.
    public func crop(x: Int, y: Int, width w: Int, height h: Int) -> Plane {
        precondition(x >= 0 && y >= 0 && x + w <= width && y + h <= height, "Crop out of bounds")
        var out = [Float](repeating: 0, count: w * h)
        values.withUnsafeBufferPointer { src in
            for row in 0..<h {
                let s = (y + row) * width + x
                for col in 0..<w { out[row * w + col] = src[s + col] }
            }
        }
        return Plane(width: w, height: h, values: out)
    }
}

/// The structural similarity index (Wang et al. 2004), computed over square windows.
///
/// Uses uniform windows with a stride instead of the 11x11 Gaussian of the paper. That keeps it
/// fast enough for full @3x screens in debug builds, and the ranking of images is the same.
public enum SSIM {
    public struct Result: Sendable {
        /// Mean SSIM over all windows, in -1...1 (1 means identical).
        public let score: Double
        /// Per-window SSIM, `mapWidth` x `mapHeight`, useful as a heat map.
        public let map: [Float]
        public let mapWidth: Int
        public let mapHeight: Int
        public let window: Int
        public let stride: Int
    }

    static let c1 = pow(0.01 * 255.0, 2.0)
    static let c2 = pow(0.03 * 255.0, 2.0)

    public static func compute(_ a: Plane, _ b: Plane, window: Int = 8, stride: Int = 4) -> Result {
        precondition(a.width == b.width && a.height == b.height, "SSIM needs planes of the same size")
        let win = max(1, min(window, a.width, a.height))
        let step = max(1, stride)
        let mapW = (a.width - win) / step + 1
        let mapH = (a.height - win) / step + 1
        var map = [Float](repeating: 0, count: mapW * mapH)
        let n = Double(win * win)
        var total = 0.0

        a.values.withUnsafeBufferPointer { pa in
            b.values.withUnsafeBufferPointer { pb in
                for my in 0..<mapH {
                    let y0 = my * step
                    for mx in 0..<mapW {
                        let x0 = mx * step
                        var sa = 0.0, sb = 0.0, saa = 0.0, sbb = 0.0, sab = 0.0
                        for y in y0..<(y0 + win) {
                            let row = y * a.width
                            for x in x0..<(x0 + win) {
                                let va = Double(pa[row + x]), vb = Double(pb[row + x])
                                sa += va
                                sb += vb
                                saa += va * va
                                sbb += vb * vb
                                sab += va * vb
                            }
                        }
                        let ma = sa / n, mb = sb / n
                        let varA = max(0, saa / n - ma * ma)
                        let varB = max(0, sbb / n - mb * mb)
                        let cov = sab / n - ma * mb
                        let s = ((2 * ma * mb + c1) * (2 * cov + c2)) / ((ma * ma + mb * mb + c1) * (varA + varB + c2))
                        map[my * mapW + mx] = Float(s)
                        total += s
                    }
                }
            }
        }
        return Result(
            score: total / Double(mapW * mapH),
            map: map,
            mapWidth: mapW,
            mapHeight: mapH,
            window: win,
            stride: step
        )
    }
}

extension SSIM {
    /// How a colour image is reduced to a score.
    public enum ColorMode: String, Sendable, Codable, CaseIterable {
        /// Mean of the SSIM of the red, green and blue channels. Catches hue changes that keep
        /// the same brightness (a blue button turned red), which luma alone misses.
        case rgb
        /// SSIM of Rec. 709 luma only. Faster, blind to iso-luminant colour changes.
        case luma
    }

    /// SSIM of two images of the same size, after shifting the candidate by `offset`.
    public static func compute(
        _ reference: RGBAImage,
        _ candidate: RGBAImage,
        offset: OffsetSearch.Offset = .zero,
        mode: ColorMode = .rgb,
        window: Int = 8,
        stride: Int = 4
    ) -> Double {
        precondition(reference.width == candidate.width && reference.height == candidate.height, "SSIM needs images of the same size")
        let o = OffsetSearch.overlap(width: reference.width, height: reference.height, offset: offset)
        guard o.width > 0, o.height > 0 else { return 0 }
        func score(_ a: Plane, _ b: Plane) -> Double {
            let ra = offset == .zero ? a : a.crop(x: o.refX, y: o.refY, width: o.width, height: o.height)
            let rb = offset == .zero ? b : b.crop(x: o.candX, y: o.candY, width: o.width, height: o.height)
            return compute(ra, rb, window: window, stride: stride).score
        }
        switch mode {
        case .luma:
            return score(Plane(reference), Plane(candidate))
        case .rgb:
            let total = (0...2).reduce(0.0) { $0 + score(Plane(reference, channel: $1), Plane(candidate, channel: $1)) }
            return total / 3
        }
    }
}

/// Finds the integer translation that best aligns a candidate with a reference.
public enum OffsetSearch {
    public struct Offset: Equatable, Hashable, Sendable, Codable {
        /// Candidate pixel (x + dx, y + dy) matches reference pixel (x, y).
        public var dx: Int
        public var dy: Int

        public init(dx: Int, dy: Int) {
            self.dx = dx
            self.dy = dy
        }

        public static let zero = Offset(dx: 0, dy: 0)
        public var magnitude: Double { (Double(dx * dx + dy * dy)).squareRoot() }
    }

    /// Tries every shift within `maxShift` pixels on each axis and keeps the one with the lowest
    /// mean absolute luma difference over the overlap. Ties go to the smallest shift, so an
    /// aligned pair always reports `.zero`. `sampleStep` subsamples pixels to keep it fast.
    public static func best(reference: Plane, candidate: Plane, maxShift: Int, sampleStep: Int = 2) -> Offset {
        guard maxShift > 0 else { return .zero }
        let w = reference.width, h = reference.height
        var shifts: [Offset] = []
        for dy in -maxShift...maxShift {
            for dx in -maxShift...maxShift { shifts.append(Offset(dx: dx, dy: dy)) }
        }
        shifts.sort { ($0.dx * $0.dx + $0.dy * $0.dy) < ($1.dx * $1.dx + $1.dy * $1.dy) }

        var best = Offset.zero
        var bestScore = Double.infinity
        let step = max(1, sampleStep)
        reference.values.withUnsafeBufferPointer { r in
            candidate.values.withUnsafeBufferPointer { c in
                for s in shifts {
                    let xs = max(0, -s.dx), xe = min(w, w - s.dx)
                    let ys = max(0, -s.dy), ye = min(h, h - s.dy)
                    guard xe > xs, ye > ys else { continue }
                    var sum = 0.0
                    var count = 0
                    var y = ys
                    while y < ye {
                        let rr = y * w, cr = (y + s.dy) * w + s.dx
                        var x = xs
                        while x < xe {
                            sum += Double(abs(r[rr + x] - c[cr + x]))
                            count += 1
                            x += step
                        }
                        y += step
                    }
                    let score = sum / Double(max(1, count))
                    // A shift has to win clearly, otherwise noise picks a random direction.
                    if score + 1e-9 < bestScore {
                        bestScore = score
                        best = s
                    }
                }
            }
        }
        return best
    }

    /// The overlapping rectangles of reference and candidate for `offset`.
    static func overlap(width w: Int, height h: Int, offset: Offset)
        -> (refX: Int, refY: Int, candX: Int, candY: Int, width: Int, height: Int)
    {
        let refX = max(0, -offset.dx), refY = max(0, -offset.dy)
        let ow = w - abs(offset.dx), oh = h - abs(offset.dy)
        return (refX, refY, refX + offset.dx, refY + offset.dy, max(0, ow), max(0, oh))
    }
}
