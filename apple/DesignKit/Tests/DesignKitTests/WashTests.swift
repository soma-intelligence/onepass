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

    @Test func fullStrengthIsAllGreen() throws {
        // 4 of 4 segments lit: every lit segment is green, never a rainbow end to end.
        let colors = StrengthMeter.segmentColors(forBits: 120)
        #expect(colors.count == 4)
        for color in colors {
            #expect(close(try #require(color), .green))
        }
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

    @Test func strengthMeterSegmentsTakeTheLevelColor() throws {
        // 65 bits is level 2: two lit segments, both the scale color at 2/4, the rest unlit.
        let colors = StrengthMeter.segmentColors(forBits: 65)
        #expect(colors.count == 4)
        for color in colors.prefix(2) {
            #expect(close(try #require(color), Theme.Wash.scaleColor(at: 0.5)))
        }
        #expect(colors.suffix(2).allSatisfy { $0 == nil })
        #expect(StrengthMeter.segmentColors(forBits: 45).map { $0 != nil } == [true, false, false, false])
    }
}
