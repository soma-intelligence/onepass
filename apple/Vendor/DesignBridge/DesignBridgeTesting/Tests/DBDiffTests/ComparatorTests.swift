import CoreGraphics
import Foundation
import Testing
@testable import DBDiff

@Suite("Image comparator")
struct ComparatorTests {
    @Test func identicalPasses() throws {
        let img = Fixtures.screen()
        let r = try ImageComparator.compare(reference: img, candidate: img, name: "same")
        #expect(r.passed)
        #expect(r.ssim > 0.9999)
        #expect(r.offset == .zero)
        #expect(r.changedPixelRatio == 0)
        #expect(r.changedBounds == nil)
        #expect(r.failures.isEmpty)
    }

    @Test func colourChangeFailsAndIsLocalised() throws {
        let ref = Fixtures.screen()
        let cand = Fixtures.screen(buttonColor: RGBA(230, 40, 40))
        let r = try ImageComparator.compare(reference: ref, candidate: cand, options: .init(ssimThreshold: 0.995))
        #expect(!r.passed)
        #expect(r.failures.contains { $0.contains("SSIM") })
        let bounds = try #require(r.changedBounds)
        // The button sits at x 20...100, y 150...174 (scale 1 in these fixtures).
        #expect(bounds.minX >= 20 && bounds.maxX <= 100)
        #expect(bounds.minY >= 150 && bounds.maxY <= 174)
        #expect(r.changedPixelRatio > 0 && r.changedPixelRatio < 0.1)
    }

    @Test func shiftWithinToleranceIsAbsorbed() throws {
        // 1 pt at @3x is 3 px; a 2 px shift must be found and forgiven.
        let ref = Fixtures.screen()
        let cand = Fixtures.screen(shift: (2, 0))
        let r = try ImageComparator.compare(reference: ref, candidate: cand, options: .init(maxOffsetPoints: 1, scale: 3))
        #expect(r.offset == .init(dx: 2, dy: 0))
        #expect(r.ssim > r.ssimAtZeroOffset)
        #expect(r.ssim > 0.99)
        #expect(r.passed)
        #expect(abs(r.offsetPoints - 2.0 / 3.0) < 1e-9)
    }

    @Test func shiftBeyondToleranceFails() throws {
        let ref = Fixtures.screen()
        let cand = Fixtures.screen(shift: (0, 6))
        let r = try ImageComparator.compare(reference: ref, candidate: cand, options: .init(ssimThreshold: 0.97, maxOffsetPoints: 1, scale: 3))
        // The search radius is 3 px, so the 6 px shift cannot be absorbed.
        #expect(!r.passed)
        #expect(abs(r.offset.dy) <= 3)
    }

    @Test func masksHideDifferences() throws {
        let ref = Fixtures.screen()
        let cand = Fixtures.screen(buttonColor: RGBA(230, 40, 40))
        let mask = CGRect(x: 20, y: 150, width: 80, height: 24)
        let r = try ImageComparator.compare(reference: ref, candidate: cand, options: .init(ssimThreshold: 0.9999, scale: 1, masks: [mask]))
        #expect(r.passed)
        #expect(r.changedPixelRatio == 0)
    }

    @Test func masksAreInPoints() throws {
        var ref = RGBAImage(width: 30, height: 30, fill: .white)
        var cand = ref
        cand[4, 4] = .black
        // A 2 x 2 pt mask at @3x covers pixels 0...5.
        ImageComparator.applyMasks([CGRect(x: 0, y: 0, width: 2, height: 2)], scale: 3, reference: &ref, candidate: &cand)
        #expect(ref == cand)
        #expect(ref[5, 5] == RGBA(128, 128, 128))
        #expect(ref[6, 6] == .white)
    }

    @Test func candidateIsResampledWhenAspectMatches() throws {
        let ref = Fixtures.screen(width: 120, height: 200)
        let cand = try ref.resized(to: CGSize(width: 60, height: 100))
        let r = try ImageComparator.compare(reference: ref, candidate: cand, options: .init(ssimThreshold: 0.8))
        #expect(r.candidateWasResized)
        #expect(r.diffImage.width == 120 && r.diffImage.height == 200)
        #expect(r.ssim > 0.8)
    }

    @Test func aspectMismatchThrows() {
        let ref = Fixtures.screen(width: 120, height: 200)
        let cand = Fixtures.screen(width: 120, height: 150)
        #expect(throws: DBDiffError.self) {
            try ImageComparator.compare(reference: ref, candidate: cand)
        }
    }

    @Test func noResizeOptionThrowsOnSizeMismatch() throws {
        let ref = Fixtures.screen(width: 120, height: 200)
        let cand = try ref.resized(to: CGSize(width: 60, height: 100))
        #expect(throws: DBDiffError.self) {
            try ImageComparator.compare(reference: ref, candidate: cand, options: .init(resizeCandidate: false))
        }
    }

    @Test func diffImageMarksChangesInRedAndKeepsTheRestGrey() {
        let ref = RGBAImage(width: 10, height: 10, fill: .white)
        var cand = ref
        cand[3, 4] = .black
        let d = ImageComparator.diffImage(reference: ref, candidate: cand, offset: .zero, tolerance: 8)
        let changed = d.image[3, 4]
        #expect(changed.r > changed.g && changed.r > changed.b)
        let same = d.image[0, 0]
        #expect(same.r == same.g && same.g == same.b)
        #expect(d.bounds == CGRect(x: 3, y: 4, width: 1, height: 1))
        #expect(abs(d.ratio - 0.01) < 1e-9)
    }

    @Test func diffToleranceIgnoresSmallChanges() {
        let ref = RGBAImage(width: 4, height: 4, fill: RGBA(100, 100, 100))
        let cand = RGBAImage(width: 4, height: 4, fill: RGBA(105, 100, 100))
        let d = ImageComparator.diffImage(reference: ref, candidate: cand, offset: .zero, tolerance: 8)
        #expect(d.ratio == 0)
        #expect(d.bounds == nil)
    }

    @Test func diffMarksPixelsOutsideTheOverlap() {
        let ref = RGBAImage(width: 6, height: 6, fill: .white)
        let d = ImageComparator.diffImage(reference: ref, candidate: ref, offset: .init(dx: 2, dy: 0), tolerance: 8)
        // Columns 4 and 5 map outside the candidate.
        #expect(d.image[5, 0] == RGBA(120, 160, 230))
        #expect(d.image[0, 0].r == d.image[0, 0].b)
    }

    @Test func maxShiftPixelsRoundsDown() {
        #expect(ComparisonOptions(maxOffsetPoints: 1, scale: 3).maxShiftPixels == 3)
        #expect(ComparisonOptions(maxOffsetPoints: 0.5, scale: 3).maxShiftPixels == 1)
        #expect(ComparisonOptions(maxOffsetPoints: 0, scale: 3).maxShiftPixels == 0)
    }
}

@Suite("PNG round trip")
struct RGBAImageTests {
    @Test func pngRoundTripIsLossless() throws {
        let img = Fixtures.screen()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("dbdiff-\(UUID().uuidString).png")
        defer { try? FileManager.default.removeItem(at: url) }
        try img.writePNG(to: url)
        let back = try RGBAImage(contentsOf: url)
        #expect(back == img)
    }

    @Test func transparencyIsFlattenedOverTheBackground() throws {
        // A fully transparent 2 x 2 image becomes the background colour.
        let space = CGColorSpace(name: CGColorSpace.sRGB)!
        let ctx = CGContext(data: nil, width: 2, height: 2, bitsPerComponent: 8, bytesPerRow: 8, space: space,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        let clear = try RGBAImage(cgImage: ctx.makeImage()!, background: RGBA(10, 20, 30))
        #expect(clear[1, 1] == RGBA(10, 20, 30))
    }

    @Test func lumaUsesRec709Weights() {
        let img = RGBAImage(width: 1, height: 1, fill: RGBA(255, 0, 0))
        #expect(abs(img.luma()[0] - 0.2126 * 255) < 0.01)
    }
}
