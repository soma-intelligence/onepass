import SwiftUI
import Testing

@testable import DesignKit

@Suite("Wash")
struct WashTests {
    private func close(_ a: Color, _ b: Color) -> Bool {
        let env = EnvironmentValues()
        let x = a.resolve(in: env)
        let y = b.resolve(in: env)
        let tolerance: Float = 0.01
        return abs(x.red - y.red) < tolerance && abs(x.green - y.green) < tolerance
            && abs(x.blue - y.blue) < tolerance && abs(x.opacity - y.opacity) < tolerance
    }

    @Test func scaleEnds() {
        #expect(close(Theme.Wash.scaleColor(at: -1), .red))
        #expect(close(Theme.Wash.scaleColor(at: 0.8), .green))
        #expect(close(Theme.Wash.scaleColor(at: 2), .green))
    }

    @Test func fullStrengthIsAllGreen() {
        // 4 of 4 segments lit: green from the third one, never a rainbow end to end.
        #expect(close(Theme.Wash.segmentColor(index: 3, of: 4), .green))
        #expect(close(Theme.Wash.segmentColor(index: 2, of: 4), Theme.Wash.scaleColor(at: 0.75)))
    }

    @Test("Thresholds agree with StrengthMeter", arguments: [40.0, 60, 80, 100])
    func thresholds(bits: Double) {
        let level = StrengthMeter.level(forBits: bits)
        #expect(level == [40.0, 60, 80, 100].firstIndex(of: bits)! + 1)
    }

    @Test func countdownUnchanged() {
        #expect(close(Theme.Wash.countdownColor(Theme.accent, secondsLeft: 10), Theme.accent))
        #expect(close(Theme.Wash.countdownColor(Theme.accent, secondsLeft: 4), .red))
    }

    @Test func flatFallback() {
        #expect(Theme.Wash.isFlat(increaseContrast: true, reduceTransparency: false))
        #expect(Theme.Wash.isFlat(increaseContrast: false, reduceTransparency: true))
        #expect(!Theme.Wash.isFlat(increaseContrast: false, reduceTransparency: false))
    }

    @Test func emptyScoreShowsTrackOnly() {
        #expect(!Theme.Wash.scaleShowsFill(score: nil))
        #expect(!Theme.Wash.scaleShowsFill(score: 0))
        #expect(Theme.Wash.scaleShowsFill(score: 1))
    }

    @Test func strengthMeterSegmentsFollowTheScale() {
        let colors = StrengthMeter.segmentColors(forBits: 120)
        #expect(colors.count == 4)
        for i in 0..<4 {
            let c = try! #require(colors[i])
            #expect(close(c, Theme.Wash.segmentColor(index: i, of: 4)))
        }
        #expect(close(colors[3]!, .green))
        #expect(StrengthMeter.segmentColors(forBits: 45).map { $0 != nil } == [true, false, false, false])
    }
}
