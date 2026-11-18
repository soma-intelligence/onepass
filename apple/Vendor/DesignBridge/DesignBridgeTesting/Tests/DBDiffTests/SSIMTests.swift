import Testing
@testable import DBDiff

@Suite("SSIM")
struct SSIMTests {
    @Test func identicalImagesScoreOne() {
        let a = Plane(Fixtures.screen())
        let r = SSIM.compute(a, a)
        #expect(abs(r.score - 1) < 1e-9)
        #expect(r.map.allSatisfy { abs($0 - 1) < 1e-5 })
    }

    @Test func flatIdenticalRegionsScoreOne() {
        let a = Plane(RGBAImage(width: 32, height: 32, fill: .white))
        #expect(abs(SSIM.compute(a, a).score - 1) < 1e-9)
    }

    @Test func scoreFallsAsNoiseGrows() {
        let base = Fixtures.screen()
        let a = Plane(base)
        let light = SSIM.compute(a, Plane(Fixtures.noisy(base, amount: 4))).score
        let heavy = SSIM.compute(a, Plane(Fixtures.noisy(base, amount: 40))).score
        #expect(light < 1)
        #expect(light > 0.9)
        #expect(heavy < light)
        #expect(heavy < 0.8)
    }

    @Test func invertedImageScoresLow() {
        let base = Fixtures.screen()
        var inverted = base
        for i in 0..<inverted.pixels.count where i % 4 != 3 { inverted.pixels[i] = 255 - inverted.pixels[i] }
        let s = SSIM.compute(Plane(base), Plane(inverted)).score
        #expect(s < 0.3)
    }

    @Test func isSymmetric() {
        let a = Plane(Fixtures.screen())
        let b = Plane(Fixtures.noisy(Fixtures.screen(), amount: 12))
        #expect(abs(SSIM.compute(a, b).score - SSIM.compute(b, a).score) < 1e-9)
    }

    @Test func mapHasExpectedShape() {
        let a = Plane(Fixtures.screen(width: 40, height: 24))
        let r = SSIM.compute(a, a, window: 8, stride: 4)
        #expect(r.mapWidth == (40 - 8) / 4 + 1)
        #expect(r.mapHeight == (24 - 8) / 4 + 1)
        #expect(r.map.count == r.mapWidth * r.mapHeight)
    }

    @Test func windowShrinksForTinyImages() {
        let a = Plane(RGBAImage(width: 3, height: 5, fill: .black))
        let r = SSIM.compute(a, a, window: 8)
        #expect(r.window == 3)
        #expect(abs(r.score - 1) < 1e-9)
    }
}

@Suite("Offset search")
struct OffsetSearchTests {
    @Test func alignedPairReportsZero() {
        let a = Plane(Fixtures.screen())
        #expect(OffsetSearch.best(reference: a, candidate: a, maxShift: 3) == .zero)
    }

    @Test(arguments: [(2, 0), (0, -3), (-1, 2), (3, 3)])
    func findsKnownShift(dx: Int, dy: Int) {
        let ref = Plane(Fixtures.screen())
        let cand = Plane(Fixtures.screen(shift: (dx, dy)))
        #expect(OffsetSearch.best(reference: ref, candidate: cand, maxShift: 3, sampleStep: 1) == .init(dx: dx, dy: dy))
    }

    @Test func zeroRadiusNeverSearches() {
        let ref = Plane(Fixtures.screen())
        let cand = Plane(Fixtures.screen(shift: (2, 0)))
        #expect(OffsetSearch.best(reference: ref, candidate: cand, maxShift: 0) == .zero)
    }

    @Test func overlapGeometry() {
        let o = OffsetSearch.overlap(width: 10, height: 8, offset: .init(dx: 2, dy: -1))
        #expect(o.refX == 0 && o.refY == 1)
        #expect(o.candX == 2 && o.candY == 0)
        #expect(o.width == 8 && o.height == 7)
    }
}

@Suite("Colour SSIM")
struct ColourSSIMTests {
    @Test func rgbModeCatchesIsoLuminantHueChange() {
        // Blue (20, 90, 220) and red (230, 40, 40) have almost the same luma.
        let ref = Fixtures.screen()
        let cand = Fixtures.screen(buttonColor: RGBA(230, 40, 40))
        let luma = SSIM.compute(ref, cand, mode: .luma)
        let rgb = SSIM.compute(ref, cand, mode: .rgb)
        #expect(luma > 0.99)
        #expect(rgb < luma - 0.02)
    }

    @Test func shiftedComputeUsesTheOverlap() {
        let ref = Fixtures.screen()
        let cand = Fixtures.screen(shift: (2, 1))
        let aligned = SSIM.compute(ref, cand, offset: .init(dx: 2, dy: 1))
        let unaligned = SSIM.compute(ref, cand)
        #expect(aligned > 0.999)
        #expect(unaligned < aligned)
    }
}
